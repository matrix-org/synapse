# -*- coding: utf-8 -*-
# Copyright 2020 Quentin Gliech
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from typing import TYPE_CHECKING, Dict, Generic, List, Optional, Tuple, TypeVar
from urllib.parse import urlencode

import attr
import pymacaroons
from authlib.common.security import generate_token
from authlib.jose import JsonWebToken
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oidc.core import CodeIDToken, ImplicitIDToken, UserInfo
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url
from jinja2 import Environment, Template
from pymacaroons.exceptions import (
    MacaroonDeserializationException,
    MacaroonInvalidSignatureException,
)
from typing_extensions import TypedDict

from twisted.web.client import readBody

from synapse.config import ConfigError
from synapse.http.server import respond_with_html
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable
from synapse.types import JsonDict, UserID, map_username_to_mxid_localpart
from synapse.util import json_decoder

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = b"oidc_session"

#: A token exchanged from the token endpoint, as per RFC6749 sec 5.1. and
#: OpenID.Core sec 3.1.3.3.
Token = TypedDict(
    "Token",
    {
        "access_token": str,
        "token_type": str,
        "id_token": Optional[str],
        "refresh_token": Optional[str],
        "expires_in": int,
        "scope": Optional[str],
    },
)

#: A JWK, as per RFC7517 sec 4. The type could be more precise than that, but
#: there is no real point of doing this in our case.
JWK = Dict[str, str]

#: A JWK Set, as per RFC7517 sec 5.
JWKS = TypedDict("JWKS", {"keys": List[JWK]})


class OidcError(Exception):
    """Used to catch errors when calling the token_endpoint
    """

    def __init__(self, error, error_description=None):
        self.error = error
        self.error_description = error_description

    def __str__(self):
        if self.error_description:
            return "{}: {}".format(self.error, self.error_description)
        return self.error


class MappingException(Exception):
    """Used to catch errors when mapping the UserInfo object
    """


class OidcHandler:
    """Handles requests related to the OpenID Connect login flow.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self._callback_url = hs.config.oidc_callback_url  # type: str
        self._scopes = hs.config.oidc_scopes  # type: List[str]
        self._client_auth = ClientAuth(
            hs.config.oidc_client_id,
            hs.config.oidc_client_secret,
            hs.config.oidc_client_auth_method,
        )  # type: ClientAuth
        self._client_auth_method = hs.config.oidc_client_auth_method  # type: str
        self._provider_metadata = OpenIDProviderMetadata(
            issuer=hs.config.oidc_issuer,
            authorization_endpoint=hs.config.oidc_authorization_endpoint,
            token_endpoint=hs.config.oidc_token_endpoint,
            userinfo_endpoint=hs.config.oidc_userinfo_endpoint,
            jwks_uri=hs.config.oidc_jwks_uri,
        )  # type: OpenIDProviderMetadata
        self._provider_needs_discovery = hs.config.oidc_discover  # type: bool
        self._user_mapping_provider = hs.config.oidc_user_mapping_provider_class(
            hs.config.oidc_user_mapping_provider_config
        )  # type: OidcMappingProvider
        self._skip_verification = hs.config.oidc_skip_verification  # type: bool
        self._allow_existing_users = hs.config.oidc_allow_existing_users  # type: bool

        self._http_client = hs.get_proxied_http_client()
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()
        self._datastore = hs.get_datastore()
        self._clock = hs.get_clock()
        self._hostname = hs.hostname  # type: str
        self._server_name = hs.config.server_name  # type: str
        self._macaroon_secret_key = hs.config.macaroon_secret_key
        self._error_template = hs.config.sso_error_template

        # identifier for the external_ids table
        self._auth_provider_id = "oidc"

    def _render_error(
        self, request, error: str, error_description: Optional[str] = None
    ) -> None:
        """Render the error template and respond to the request with it.

        This is used to show errors to the user. The template of this page can
        be found under `synapse/res/templates/sso_error.html`.

        Args:
            request: The incoming request from the browser.
                We'll respond with an HTML page describing the error.
            error: A technical identifier for this error. Those include
                well-known OAuth2/OIDC error types like invalid_request or
                access_denied.
            error_description: A human-readable description of the error.
        """
        html = self._error_template.render(
            error=error, error_description=error_description
        )
        respond_with_html(request, 400, html)

    def _validate_metadata(self):
        """Verifies the provider metadata.

        This checks the validity of the currently loaded provider. Not
        everything is checked, only:

          - ``issuer``
          - ``authorization_endpoint``
          - ``token_endpoint``
          - ``response_types_supported`` (checks if "code" is in it)
          - ``jwks_uri``

        Raises:
            ValueError: if something in the provider is not valid
        """
        # Skip verification to allow non-compliant providers (e.g. issuers not running on a secure origin)
        if self._skip_verification is True:
            return

        m = self._provider_metadata
        m.validate_issuer()
        m.validate_authorization_endpoint()
        m.validate_token_endpoint()

        if m.get("token_endpoint_auth_methods_supported") is not None:
            m.validate_token_endpoint_auth_methods_supported()
            if (
                self._client_auth_method
                not in m["token_endpoint_auth_methods_supported"]
            ):
                raise ValueError(
                    '"{auth_method}" not in "token_endpoint_auth_methods_supported" ({supported!r})'.format(
                        auth_method=self._client_auth_method,
                        supported=m["token_endpoint_auth_methods_supported"],
                    )
                )

        if m.get("response_types_supported") is not None:
            m.validate_response_types_supported()

            if "code" not in m["response_types_supported"]:
                raise ValueError(
                    '"code" not in "response_types_supported" (%r)'
                    % (m["response_types_supported"],)
                )

        # If the openid scope was not requested, we need a userinfo endpoint to fetch user infos
        if self._uses_userinfo:
            if m.get("userinfo_endpoint") is None:
                raise ValueError(
                    'provider has no "userinfo_endpoint", even though it is required because the "openid" scope is not requested'
                )
        else:
            # If we're not using userinfo, we need a valid jwks to validate the ID token
            if m.get("jwks") is None:
                if m.get("jwks_uri") is not None:
                    m.validate_jwks_uri()
                else:
                    raise ValueError('"jwks_uri" must be set')

    @property
    def _uses_userinfo(self) -> bool:
        """Returns True if the ``userinfo_endpoint`` should be used.

        This is based on the requested scopes: if the scopes include
        ``openid``, the provider should give use an ID token containing the
        user informations. If not, we should fetch them using the
        ``access_token`` with the ``userinfo_endpoint``.
        """

        # Maybe that should be user-configurable and not inferred?
        return "openid" not in self._scopes

    async def load_metadata(self) -> OpenIDProviderMetadata:
        """Load and validate the provider metadata.

        The values metadatas are discovered if ``oidc_config.discovery`` is
        ``True`` and then cached.

        Raises:
            ValueError: if something in the provider is not valid

        Returns:
            The provider's metadata.
        """
        # If we are using the OpenID Discovery documents, it needs to be loaded once
        # FIXME: should there be a lock here?
        if self._provider_needs_discovery:
            url = get_well_known_url(self._provider_metadata["issuer"], external=True)
            metadata_response = await self._http_client.get_json(url)
            # TODO: maybe update the other way around to let user override some values?
            self._provider_metadata.update(metadata_response)
            self._provider_needs_discovery = False

        self._validate_metadata()

        return self._provider_metadata

    async def load_jwks(self, force: bool = False) -> JWKS:
        """Load the JSON Web Key Set used to sign ID tokens.

        If we're not using the ``userinfo_endpoint``, user infos are extracted
        from the ID token, which is a JWT signed by keys given by the provider.
        The keys are then cached.

        Args:
            force: Force reloading the keys.

        Returns:
            The key set

            Looks like this::

                {
                    'keys': [
                        {
                            'kid': 'abcdef',
                            'kty': 'RSA',
                            'alg': 'RS256',
                            'use': 'sig',
                            'e': 'XXXX',
                            'n': 'XXXX',
                        }
                    ]
                }
        """
        if self._uses_userinfo:
            # We're not using jwt signing, return an empty jwk set
            return {"keys": []}

        # First check if the JWKS are loaded in the provider metadata.
        # It can happen either if the provider gives its JWKS in the discovery
        # document directly or if it was already loaded once.
        metadata = await self.load_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set is not None and not force:
            return jwk_set

        # Loading the JWKS using the `jwks_uri` metadata
        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        jwk_set = await self._http_client.get_json(uri)

        # Caching the JWKS in the provider's metadata
        self._provider_metadata["jwks"] = jwk_set
        return jwk_set

    async def _exchange_code(self, code: str) -> Token:
        """Exchange an authorization code for a token.

        This calls the ``token_endpoint`` with the authorization code we
        received in the callback to exchange it for a token. The call uses the
        ``ClientAuth`` to authenticate with the client with its ID and secret.

        See:
           https://tools.ietf.org/html/rfc6749#section-3.2
           https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        Args:
            code: The authorization code we got from the callback.

        Returns:
            A dict containing various tokens.

            May look like this::

                {
                    'token_type': 'bearer',
                    'access_token': 'abcdef',
                    'expires_in': 3599,
                    'id_token': 'ghijkl',
                    'refresh_token': 'mnopqr',
                }

        Raises:
            OidcError: when the ``token_endpoint`` returned an error.
        """
        metadata = await self.load_metadata()
        token_endpoint = metadata.get("token_endpoint")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self._http_client.user_agent,
            "Accept": "application/json",
        }

        args = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._callback_url,
        }
        body = urlencode(args, True)

        # Fill the body/headers with credentials
        uri, headers, body = self._client_auth.prepare(
            method="POST", uri=token_endpoint, headers=headers, body=body
        )
        headers = {k: [v] for (k, v) in headers.items()}

        # Do the actual request
        # We're not using the SimpleHttpClient util methods as we don't want to
        # check the HTTP status code and we do the body encoding ourself.
        response = await self._http_client.request(
            method="POST", uri=uri, data=body.encode("utf-8"), headers=headers,
        )

        # This is used in multiple error messages below
        status = "{code} {phrase}".format(
            code=response.code, phrase=response.phrase.decode("utf-8")
        )

        resp_body = await make_deferred_yieldable(readBody(response))

        if response.code >= 500:
            # In case of a server error, we should first try to decode the body
            # and check for an error field. If not, we respond with a generic
            # error message.
            try:
                resp = json_decoder.decode(resp_body.decode("utf-8"))
                error = resp["error"]
                description = resp.get("error_description", error)
            except (ValueError, KeyError):
                # Catch ValueError for the JSON decoding and KeyError for the "error" field
                error = "server_error"
                description = (
                    (
                        'Authorization server responded with a "{status}" error '
                        "while exchanging the authorization code."
                    ).format(status=status),
                )

            raise OidcError(error, description)

        # Since it is a not a 5xx code, body should be a valid JSON. It will
        # raise if not.
        resp = json_decoder.decode(resp_body.decode("utf-8"))

        if "error" in resp:
            error = resp["error"]
            # In case the authorization server responded with an error field,
            # it should be a 4xx code. If not, warn about it but don't do
            # anything special and report the original error message.
            if response.code < 400:
                logger.debug(
                    "Invalid response from the authorization server: "
                    'responded with a "{status}" '
                    "but body has an error field: {error!r}".format(
                        status=status, error=resp["error"]
                    )
                )

            description = resp.get("error_description", error)
            raise OidcError(error, description)

        # Now, this should not be an error. According to RFC6749 sec 5.1, it
        # should be a 200 code. We're a bit more flexible than that, and will
        # only throw on a 4xx code.
        if response.code >= 400:
            description = (
                'Authorization server responded with a "{status}" error '
                'but did not include an "error" field in its response.'.format(
                    status=status
                )
            )
            logger.warning(description)
            # Body was still valid JSON. Might be useful to log it for debugging.
            logger.warning("Code exchange response: {resp!r}".format(resp=resp))
            raise OidcError("server_error", description)

        return resp

    async def _fetch_userinfo(self, token: Token) -> UserInfo:
        """Fetch user informations from the ``userinfo_endpoint``.

        Args:
            token: the token given by the ``token_endpoint``.
                Must include an ``access_token`` field.

        Returns:
            UserInfo: an object representing the user.
        """
        metadata = await self.load_metadata()

        resp = await self._http_client.get_json(
            metadata["userinfo_endpoint"],
            headers={"Authorization": ["Bearer {}".format(token["access_token"])]},
        )

        return UserInfo(resp)

    async def _parse_id_token(self, token: Token, nonce: str) -> UserInfo:
        """Return an instance of UserInfo from token's ``id_token``.

        Args:
            token: the token given by the ``token_endpoint``.
                Must include an ``id_token`` field.
            nonce: the nonce value originally sent in the initial authorization
                request. This value should match the one inside the token.

        Returns:
            An object representing the user.
        """
        metadata = await self.load_metadata()
        claims_params = {
            "nonce": nonce,
            "client_id": self._client_auth.client_id,
        }
        if "access_token" in token:
            # If we got an `access_token`, there should be an `at_hash` claim
            # in the `id_token` that we can check against.
            claims_params["access_token"] = token["access_token"]
            claims_cls = CodeIDToken
        else:
            claims_cls = ImplicitIDToken

        alg_values = metadata.get("id_token_signing_alg_values_supported", ["RS256"])

        jwt = JsonWebToken(alg_values)

        claim_options = {"iss": {"values": [metadata["issuer"]]}}

        # Try to decode the keys in cache first, then retry by forcing the keys
        # to be reloaded
        jwk_set = await self.load_jwks()
        try:
            claims = jwt.decode(
                token["id_token"],
                key=jwk_set,
                claims_cls=claims_cls,
                claims_options=claim_options,
                claims_params=claims_params,
            )
        except ValueError:
            logger.info("Reloading JWKS after decode error")
            jwk_set = await self.load_jwks(force=True)  # try reloading the jwks
            claims = jwt.decode(
                token["id_token"],
                key=jwk_set,
                claims_cls=claims_cls,
                claims_options=claim_options,
                claims_params=claims_params,
            )

        claims.validate(leeway=120)  # allows 2 min of clock skew
        return UserInfo(claims)

    async def handle_redirect_request(
        self,
        request: SynapseRequest,
        client_redirect_url: bytes,
        ui_auth_session_id: Optional[str] = None,
    ) -> str:
        """Handle an incoming request to /login/sso/redirect

        It returns a redirect to the authorization endpoint with a few
        parameters:

          - ``client_id``: the client ID set in ``oidc_config.client_id``
          - ``response_type``: ``code``
          - ``redirect_uri``: the callback URL ; ``{base url}/_synapse/oidc/callback``
          - ``scope``: the list of scopes set in ``oidc_config.scopes``
          - ``state``: a random string
          - ``nonce``: a random string

        In addition generating a redirect URL, we are setting a cookie with
        a signed macaroon token containing the state, the nonce and the
        client_redirect_url params. Those are then checked when the client
        comes back from the provider.

        Args:
            request: the incoming request from the browser.
                We'll respond to it with a redirect and a cookie.
            client_redirect_url: the URL that we should redirect the client to
                when everything is done
            ui_auth_session_id: The session ID of the ongoing UI Auth (or
                None if this is a login).

        Returns:
            The redirect URL to the authorization endpoint.

        """

        state = generate_token()
        nonce = generate_token()

        cookie = self._generate_oidc_session_token(
            state=state,
            nonce=nonce,
            client_redirect_url=client_redirect_url.decode(),
            ui_auth_session_id=ui_auth_session_id,
        )
        request.addCookie(
            SESSION_COOKIE_NAME,
            cookie,
            path="/_synapse/oidc",
            max_age="3600",
            httpOnly=True,
            sameSite="lax",
        )

        metadata = await self.load_metadata()
        authorization_endpoint = metadata.get("authorization_endpoint")
        return prepare_grant_uri(
            authorization_endpoint,
            client_id=self._client_auth.client_id,
            response_type="code",
            redirect_uri=self._callback_url,
            scope=self._scopes,
            state=state,
            nonce=nonce,
        )

    async def handle_oidc_callback(self, request: SynapseRequest) -> None:
        """Handle an incoming request to /_synapse/oidc/callback

        Since we might want to display OIDC-related errors in a user-friendly
        way, we don't raise SynapseError from here. Instead, we call
        ``self._render_error`` which displays an HTML page for the error.

        Most of the OpenID Connect logic happens here:

          - first, we check if there was any error returned by the provider and
            display it
          - then we fetch the session cookie, decode and verify it
          - the ``state`` query parameter should match with the one stored in the
            session cookie
          - once we known this session is legit, exchange the code with the
            provider using the ``token_endpoint`` (see ``_exchange_code``)
          - once we have the token, use it to either extract the UserInfo from
            the ``id_token`` (``_parse_id_token``), or use the ``access_token``
            to fetch UserInfo from the ``userinfo_endpoint``
            (``_fetch_userinfo``)
          - map those UserInfo to a Matrix user (``_map_userinfo_to_user``) and
            finish the login

        Args:
            request: the incoming request from the browser.
        """

        # The provider might redirect with an error.
        # In that case, just display it as-is.
        if b"error" in request.args:
            # error response from the auth server. see:
            #  https://tools.ietf.org/html/rfc6749#section-4.1.2.1
            #  https://openid.net/specs/openid-connect-core-1_0.html#AuthError
            error = request.args[b"error"][0].decode()
            description = request.args.get(b"error_description", [b""])[0].decode()

            # Most of the errors returned by the provider could be due by
            # either the provider misbehaving or Synapse being misconfigured.
            # The only exception of that is "access_denied", where the user
            # probably cancelled the login flow. In other cases, log those errors.
            if error != "access_denied":
                logger.error("Error from the OIDC provider: %s %s", error, description)

            self._render_error(request, error, description)
            return

        # otherwise, it is presumably a successful response. see:
        #   https://tools.ietf.org/html/rfc6749#section-4.1.2

        # Fetch the session cookie
        session = request.getCookie(SESSION_COOKIE_NAME)  # type: Optional[bytes]
        if session is None:
            logger.info("No session cookie found")
            self._render_error(request, "missing_session", "No session cookie found")
            return

        # Remove the cookie. There is a good chance that if the callback failed
        # once, it will fail next time and the code will already be exchanged.
        # Removing it early avoids spamming the provider with token requests.
        request.addCookie(
            SESSION_COOKIE_NAME,
            b"",
            path="/_synapse/oidc",
            expires="Thu, Jan 01 1970 00:00:00 UTC",
            httpOnly=True,
            sameSite="lax",
        )

        # Check for the state query parameter
        if b"state" not in request.args:
            logger.info("State parameter is missing")
            self._render_error(request, "invalid_request", "State parameter is missing")
            return

        state = request.args[b"state"][0].decode()

        # Deserialize the session token and verify it.
        try:
            (
                nonce,
                client_redirect_url,
                ui_auth_session_id,
            ) = self._verify_oidc_session_token(session, state)
        except MacaroonDeserializationException as e:
            logger.exception("Invalid session")
            self._render_error(request, "invalid_session", str(e))
            return
        except MacaroonInvalidSignatureException as e:
            logger.exception("Could not verify session")
            self._render_error(request, "mismatching_session", str(e))
            return

        # Exchange the code with the provider
        if b"code" not in request.args:
            logger.info("Code parameter is missing")
            self._render_error(request, "invalid_request", "Code parameter is missing")
            return

        logger.debug("Exchanging code")
        code = request.args[b"code"][0].decode()
        try:
            token = await self._exchange_code(code)
        except OidcError as e:
            logger.exception("Could not exchange code")
            self._render_error(request, e.error, e.error_description)
            return

        logger.debug("Successfully obtained OAuth2 access token")

        # Now that we have a token, get the userinfo, either by decoding the
        # `id_token` or by fetching the `userinfo_endpoint`.
        if self._uses_userinfo:
            logger.debug("Fetching userinfo")
            try:
                userinfo = await self._fetch_userinfo(token)
            except Exception as e:
                logger.exception("Could not fetch userinfo")
                self._render_error(request, "fetch_error", str(e))
                return
        else:
            logger.debug("Extracting userinfo from id_token")
            try:
                userinfo = await self._parse_id_token(token, nonce=nonce)
            except Exception as e:
                logger.exception("Invalid id_token")
                self._render_error(request, "invalid_token", str(e))
                return

        # Pull out the user-agent and IP from the request.
        user_agent = request.requestHeaders.getRawHeaders(b"User-Agent", default=[b""])[
            0
        ].decode("ascii", "surrogateescape")
        ip_address = self.hs.get_ip_from_request(request)

        # Call the mapper to register/login the user
        try:
            user_id = await self._map_userinfo_to_user(
                userinfo, token, user_agent, ip_address
            )
        except MappingException as e:
            logger.exception("Could not map user")
            self._render_error(request, "mapping_error", str(e))
            return

        # Mapping providers might not have get_extra_attributes: only call this
        # method if it exists.
        extra_attributes = None
        get_extra_attributes = getattr(
            self._user_mapping_provider, "get_extra_attributes", None
        )
        if get_extra_attributes:
            extra_attributes = await get_extra_attributes(userinfo, token)

        # and finally complete the login
        if ui_auth_session_id:
            await self._auth_handler.complete_sso_ui_auth(
                user_id, ui_auth_session_id, request
            )
        else:
            await self._auth_handler.complete_sso_login(
                user_id, request, client_redirect_url, extra_attributes
            )

    def _generate_oidc_session_token(
        self,
        state: str,
        nonce: str,
        client_redirect_url: str,
        ui_auth_session_id: Optional[str],
        duration_in_ms: int = (60 * 60 * 1000),
    ) -> str:
        """Generates a signed token storing data about an OIDC session.

        When Synapse initiates an authorization flow, it creates a random state
        and a random nonce. Those parameters are given to the provider and
        should be verified when the client comes back from the provider.
        It is also used to store the client_redirect_url, which is used to
        complete the SSO login flow.

        Args:
            state: The ``state`` parameter passed to the OIDC provider.
            nonce: The ``nonce`` parameter passed to the OIDC provider.
            client_redirect_url: The URL the client gave when it initiated the
                flow.
            ui_auth_session_id: The session ID of the ongoing UI Auth (or
                None if this is a login).
            duration_in_ms: An optional duration for the token in milliseconds.
                Defaults to an hour.

        Returns:
            A signed macaroon token with the session informations.
        """
        macaroon = pymacaroons.Macaroon(
            location=self._server_name, identifier="key", key=self._macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = session")
        macaroon.add_first_party_caveat("state = %s" % (state,))
        macaroon.add_first_party_caveat("nonce = %s" % (nonce,))
        macaroon.add_first_party_caveat(
            "client_redirect_url = %s" % (client_redirect_url,)
        )
        if ui_auth_session_id:
            macaroon.add_first_party_caveat(
                "ui_auth_session_id = %s" % (ui_auth_session_id,)
            )
        now = self._clock.time_msec()
        expiry = now + duration_in_ms
        macaroon.add_first_party_caveat("time < %d" % (expiry,))

        return macaroon.serialize()

    def _verify_oidc_session_token(
        self, session: bytes, state: str
    ) -> Tuple[str, str, Optional[str]]:
        """Verifies and extract an OIDC session token.

        This verifies that a given session token was issued by this homeserver
        and extract the nonce and client_redirect_url caveats.

        Args:
            session: The session token to verify
            state: The state the OIDC provider gave back

        Returns:
            The nonce, client_redirect_url, and ui_auth_session_id for this session
        """
        macaroon = pymacaroons.Macaroon.deserialize(session)

        v = pymacaroons.Verifier()
        v.satisfy_exact("gen = 1")
        v.satisfy_exact("type = session")
        v.satisfy_exact("state = %s" % (state,))
        v.satisfy_general(lambda c: c.startswith("nonce = "))
        v.satisfy_general(lambda c: c.startswith("client_redirect_url = "))
        # Sometimes there's a UI auth session ID, it seems to be OK to attempt
        # to always satisfy this.
        v.satisfy_general(lambda c: c.startswith("ui_auth_session_id = "))
        v.satisfy_general(self._verify_expiry)

        v.verify(macaroon, self._macaroon_secret_key)

        # Extract the `nonce`, `client_redirect_url`, and maybe the
        # `ui_auth_session_id` from the token.
        nonce = self._get_value_from_macaroon(macaroon, "nonce")
        client_redirect_url = self._get_value_from_macaroon(
            macaroon, "client_redirect_url"
        )
        try:
            ui_auth_session_id = self._get_value_from_macaroon(
                macaroon, "ui_auth_session_id"
            )  # type: Optional[str]
        except ValueError:
            ui_auth_session_id = None

        return nonce, client_redirect_url, ui_auth_session_id

    def _get_value_from_macaroon(self, macaroon: pymacaroons.Macaroon, key: str) -> str:
        """Extracts a caveat value from a macaroon token.

        Args:
            macaroon: the token
            key: the key of the caveat to extract

        Returns:
            The extracted value

        Raises:
            Exception: if the caveat was not in the macaroon
        """
        prefix = key + " = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(prefix):
                return caveat.caveat_id[len(prefix) :]
        raise ValueError("No %s caveat in macaroon" % (key,))

    def _verify_expiry(self, caveat: str) -> bool:
        prefix = "time < "
        if not caveat.startswith(prefix):
            return False
        expiry = int(caveat[len(prefix) :])
        now = self._clock.time_msec()
        return now < expiry

    async def _map_userinfo_to_user(
        self, userinfo: UserInfo, token: Token, user_agent: str, ip_address: str
    ) -> str:
        """Maps a UserInfo object to a mxid.

        UserInfo should have a claim that uniquely identifies users. This claim
        is usually `sub`, but can be configured with `oidc_config.subject_claim`.
        It is then used as an `external_id`.

        If we don't find the user that way, we should register the user,
        mapping the localpart and the display name from the UserInfo.

        If a user already exists with the mxid we've mapped and allow_existing_users
        is disabled, raise an exception.

        Args:
            userinfo: an object representing the user
            token: a dict with the tokens obtained from the provider
            user_agent: The user agent of the client making the request.
            ip_address: The IP address of the client making the request.

        Raises:
            MappingException: if there was an error while mapping some properties

        Returns:
            The mxid of the user
        """
        try:
            remote_user_id = self._user_mapping_provider.get_remote_user_id(userinfo)
        except Exception as e:
            raise MappingException(
                "Failed to extract subject from OIDC response: %s" % (e,)
            )
        # Some OIDC providers use integer IDs, but Synapse expects external IDs
        # to be strings.
        remote_user_id = str(remote_user_id)

        logger.info(
            "Looking for existing mapping for user %s:%s",
            self._auth_provider_id,
            remote_user_id,
        )

        registered_user_id = await self._datastore.get_user_by_external_id(
            self._auth_provider_id, remote_user_id,
        )

        if registered_user_id is not None:
            logger.info("Found existing mapping %s", registered_user_id)
            return registered_user_id

        try:
            attributes = await self._user_mapping_provider.map_user_attributes(
                userinfo, token
            )
        except Exception as e:
            raise MappingException(
                "Could not extract user attributes from OIDC response: " + str(e)
            )

        logger.debug(
            "Retrieved user attributes from user mapping provider: %r", attributes
        )

        if not attributes["localpart"]:
            raise MappingException("localpart is empty")

        localpart = map_username_to_mxid_localpart(attributes["localpart"])

        user_id = UserID(localpart, self._hostname).to_string()
        users = await self._datastore.get_users_by_id_case_insensitive(user_id)
        if users:
            if self._allow_existing_users:
                if len(users) == 1:
                    registered_user_id = next(iter(users))
                elif user_id in users:
                    registered_user_id = user_id
                else:
                    raise MappingException(
                        "Attempted to login as '{}' but it matches more than one user inexactly: {}".format(
                            user_id, list(users.keys())
                        )
                    )
            else:
                # This mxid is taken
                raise MappingException("mxid '{}' is already taken".format(user_id))
        else:
            # It's the first time this user is logging in and the mapped mxid was
            # not taken, register the user
            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart,
                default_display_name=attributes["display_name"],
                user_agent_ips=(user_agent, ip_address),
            )
        await self._datastore.record_user_external_id(
            self._auth_provider_id, remote_user_id, registered_user_id,
        )
        return registered_user_id


UserAttribute = TypedDict(
    "UserAttribute", {"localpart": str, "display_name": Optional[str]}
)
C = TypeVar("C")


class OidcMappingProvider(Generic[C]):
    """A mapping provider maps a UserInfo object to user attributes.

    It should provide the API described by this class.
    """

    def __init__(self, config: C):
        """
        Args:
            config: A custom config object from this module, parsed by ``parse_config()``
        """

    @staticmethod
    def parse_config(config: dict) -> C:
        """Parse the dict provided by the homeserver's config

        Args:
            config: A dictionary containing configuration options for this provider

        Returns:
            A custom config object for this module
        """
        raise NotImplementedError()

    def get_remote_user_id(self, userinfo: UserInfo) -> str:
        """Get a unique user ID for this user.

        Usually, in an OIDC-compliant scenario, it should be the ``sub`` claim from the UserInfo object.

        Args:
            userinfo: An object representing the user given by the OIDC provider

        Returns:
            A unique user ID
        """
        raise NotImplementedError()

    async def map_user_attributes(
        self, userinfo: UserInfo, token: Token
    ) -> UserAttribute:
        """Map a `UserInfo` object into user attributes.

        Args:
            userinfo: An object representing the user given by the OIDC provider
            token: A dict with the tokens returned by the provider

        Returns:
            A dict containing the ``localpart`` and (optionally) the ``display_name``
        """
        raise NotImplementedError()

    async def get_extra_attributes(self, userinfo: UserInfo, token: Token) -> JsonDict:
        """Map a `UserInfo` object into additional attributes passed to the client during login.

        Args:
            userinfo: An object representing the user given by the OIDC provider
            token: A dict with the tokens returned by the provider

        Returns:
            A dict containing additional attributes. Must be JSON serializable.
        """
        return {}


# Used to clear out "None" values in templates
def jinja_finalize(thing):
    return thing if thing is not None else ""


env = Environment(finalize=jinja_finalize)


@attr.s
class JinjaOidcMappingConfig:
    subject_claim = attr.ib()  # type: str
    localpart_template = attr.ib()  # type: Template
    display_name_template = attr.ib()  # type: Optional[Template]
    extra_attributes = attr.ib()  # type: Dict[str, Template]


class JinjaOidcMappingProvider(OidcMappingProvider[JinjaOidcMappingConfig]):
    """An implementation of a mapping provider based on Jinja templates.

    This is the default mapping provider.
    """

    def __init__(self, config: JinjaOidcMappingConfig):
        self._config = config

    @staticmethod
    def parse_config(config: dict) -> JinjaOidcMappingConfig:
        subject_claim = config.get("subject_claim", "sub")

        if "localpart_template" not in config:
            raise ConfigError(
                "missing key: oidc_config.user_mapping_provider.config.localpart_template"
            )

        try:
            localpart_template = env.from_string(config["localpart_template"])
        except Exception as e:
            raise ConfigError(
                "invalid jinja template for oidc_config.user_mapping_provider.config.localpart_template: %r"
                % (e,)
            )

        display_name_template = None  # type: Optional[Template]
        if "display_name_template" in config:
            try:
                display_name_template = env.from_string(config["display_name_template"])
            except Exception as e:
                raise ConfigError(
                    "invalid jinja template for oidc_config.user_mapping_provider.config.display_name_template: %r"
                    % (e,)
                )

        extra_attributes = {}  # type Dict[str, Template]
        if "extra_attributes" in config:
            extra_attributes_config = config.get("extra_attributes") or {}
            if not isinstance(extra_attributes_config, dict):
                raise ConfigError(
                    "oidc_config.user_mapping_provider.config.extra_attributes must be a dict"
                )

            for key, value in extra_attributes_config.items():
                try:
                    extra_attributes[key] = env.from_string(value)
                except Exception as e:
                    raise ConfigError(
                        "invalid jinja template for oidc_config.user_mapping_provider.config.extra_attributes.%s: %r"
                        % (key, e)
                    )

        return JinjaOidcMappingConfig(
            subject_claim=subject_claim,
            localpart_template=localpart_template,
            display_name_template=display_name_template,
            extra_attributes=extra_attributes,
        )

    def get_remote_user_id(self, userinfo: UserInfo) -> str:
        return userinfo[self._config.subject_claim]

    async def map_user_attributes(
        self, userinfo: UserInfo, token: Token
    ) -> UserAttribute:
        localpart = self._config.localpart_template.render(user=userinfo).strip()

        display_name = None  # type: Optional[str]
        if self._config.display_name_template is not None:
            display_name = self._config.display_name_template.render(
                user=userinfo
            ).strip()

            if display_name == "":
                display_name = None

        return UserAttribute(localpart=localpart, display_name=display_name)

    async def get_extra_attributes(self, userinfo: UserInfo, token: Token) -> JsonDict:
        extras = {}  # type: Dict[str, str]
        for key, template in self._config.extra_attributes.items():
            try:
                extras[key] = template.render(user=userinfo).strip()
            except Exception as e:
                # Log an error and skip this value (don't break login for this).
                logger.error("Failed to render OIDC extra attribute %s: %s" % (key, e))
        return extras
