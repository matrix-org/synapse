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
import json
import logging
from typing import Dict, Generic, List, Optional, TypeVar
from urllib.parse import parse_qsl

import pymacaroons
from authlib.common.security import generate_token
from authlib.jose import JsonWebToken
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oidc.core import CodeIDToken, ImplicitIDToken, UserInfo
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url
from jinja2 import Environment, Template
from pymacaroons.exceptions import MacaroonDeserializationException
from typing_extensions import TypedDict

from synapse.api.errors import HttpResponseException
from synapse.config import ConfigError
from synapse.http.server import finish_request
from synapse.push.mailer import load_jinja2_templates
from synapse.server import HomeServer
from synapse.types import UserID, map_username_to_mxid_localpart

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = b"oidc_session"

#: A token exchanged from the token endpoint, as per RFC6749 sec 5.1. and OpenID.Core sec 3.1.3.3.
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


class OidcError(Exception):
    """Used to catch errors when calling the token_endpoint
    """

    def __init__(self, error, error_description=None):
        self.error = error
        self.error_description = error_description


class MappingException(Exception):
    """Used to catch errors when mapping the UserInfo object
    """


class OidcHandler:
    """Handles requests related to the OpenID Connect login flow.
    """

    def __init__(self, hs: HomeServer):
        self._callback_url = hs.config.oidc_callback_url  # type: str
        self._scopes = hs.config.oidc_scopes  # type: List[str]
        self._client_auth = ClientAuth(
            hs.config.oidc_client_id,
            hs.config.oidc_client_secret,
            hs.config.oidc_client_auth_method,
        )  # type: ClientAuth
        self._subject_claim = hs.config.oidc_subject_claim
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

        self._http_client = hs.get_proxied_http_client()
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()
        self._datastore = hs.get_datastore()
        self._macaroon_generator = hs.get_macaroon_generator()
        self._clock = hs.get_clock()
        self._hostname = hs.hostname  # type: str
        self._macaroon_secret_key = hs.config.macaroon_secret_key
        self._error_template = load_jinja2_templates(
            hs.config.oidc_template_dir, ["oidc_error.html"]
        )[0]

        # identifier for the external_ids table
        self._auth_provider_id = "oidc"

    def _render_error(
        self, request, error: str, error_description: Optional[str] = None
    ) -> None:
        """Renders the error template and respond with it.

        This is used to show errors to the user. The template of this page can
        be found under ``synapse/res/templates/oidc_error.html``.

        Args:
            request (SynapseRequest): The incoming request from the browser.
                We'll respond with an HTML page describing the error.
            error (str): A technical identifier for this error. Those include
                well-known OAuth2/OIDC error types like invalid_request or
                access_denied.
            error_description (str): A human-readable description of the error.
        """
        html_bytes = self._error_template.render(
            error=error, error_description=error_description
        ).encode("utf-8")

        request.setResponseCode(400)
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%i" % len(html_bytes))
        request.write(html_bytes)
        finish_request(request)

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

        if "response_types_supported" in m:
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
            if "jwks" not in m:
                if "jwks_uri" in m:
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
            OpenIDProviderMetadata: The providers metadata.
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

    async def load_jwks(self, force=False) -> Dict[str, List[Dict[str, str]]]:
        """Load the JSON Web Key Set used to sign ID tokens.

        If we're not using the ``userinfo_endpoint``, user infos are extracted
        from the ID token, which is a JWT signed by keys given by the provider.
        The keys are then cached.

        Args:
            force (bool): Force reloading the keys.

        Returns:
            dict: The key set

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

        metadata = await self.load_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set is not None and not force:
            return jwk_set

        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        jwk_set = await self._http_client.get_json(uri)
        self._provider_metadata["jwks"] = jwk_set
        return jwk_set

    async def _exchange_code(self, code: str) -> Token:
        """Exchange an authorization code for a token.

        This calls the ``token_endpoint`` with the authorization code we
        received in the callback to exchange it for a token. The call uses the
        ``ClientAuth`` to authenticate with the client with its ID and secret.

        Args:
            code (str): The autorization code we got from the callback.

        Returns:
            dict: contains various tokens.

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
        args = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._callback_url,
        }

        uri, headers, body = self._client_auth.prepare(
            method="POST", uri=token_endpoint, headers={}, body=""
        )
        headers = {k: [v] for (k, v) in headers.items()}
        qs = parse_qsl(body, keep_blank_values=True)
        args.update(qs)

        try:
            resp = await self._http_client.post_urlencoded_get_json(
                uri, args, headers=headers
            )
        except HttpResponseException as e:
            resp = json.loads(e.response)

        if "error" not in resp:
            return resp

        error = resp["error"]
        description = resp.get("error_description", error)
        raise OidcError(error, description)

    async def _fetch_userinfo(self, token: Token) -> UserInfo:
        """Fetch user informations from the ``userinfo_endpoint``.

        Args:
            token (dict): the token given by the ``token_endpoint``.
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
            token (dict): the token given by the ``token_endpoint``.
                Must include an ``id_token`` field.
            nonce (str): the nonce value originally sent in the initial
                authorization request. This value should match the one inside
                the token.

        Returns:
            UserInfo: an object representing the user.
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
        self, request, client_redirect_url: bytes
    ) -> None:
        """Handle an incoming request to /login/sso/redirect

        It redirects the browser to the authorization endpoint with a few
        parameters:

          - ``client_id``: the client ID set in ``oidc_config.client_id``
          - ``response_type``: ``code``
          - ``redirect_uri``: the callback URL ; ``{base url}/_synapse/oidc/callback``
          - ``scope``: the list of scopes set in ``oidc_config.scopes``
          - ``state``: a random string
          - ``nonce``: a random string

        In addition to redirecting the client, we are setting a cookie with
        a signed macaroon token containing the state, the nonce and the
        client_redirect_url params. Those are then checked when the client
        comes back from the provider.


        Args:
            request (SynapseRequest): the incoming request from the browser.
                We'll respond to it with a redirect and a cookie.
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done
        """

        state = generate_token()
        nonce = generate_token()

        cookie = self._macaroon_generator.generate_oidc_session_token(
            state=state, nonce=nonce, client_redirect_url=client_redirect_url.decode(),
        )
        request.addCookie(
            SESSION_COOKIE_NAME,
            cookie,
            path="/_synapse/oidc",
            max_age="3600",
            httpOnly=True,
        )

        metadata = await self.load_metadata()
        authorization_endpoint = metadata.get("authorization_endpoint")
        uri = prepare_grant_uri(
            authorization_endpoint,
            client_id=self._client_auth.client_id,
            response_type="code",
            redirect_uri=self._callback_url,
            scope=self._scopes,
            state=state,
            nonce=nonce,
        )
        request.redirect(uri)
        finish_request(request)

    async def handle_oidc_callback(self, request) -> None:
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
            request (SynapseRequest): the incoming request from the browser.
        """

        # The provider might redirect with an error.
        # In that case, just display it as-is.
        if b"error" in request.args:
            error = request.args[b"error"][0].decode()
            description = request.args.get(b"error_description", [b""])[0].decode()
            self._render_error(request, error, description)
            return

        # Fetch the session cookie
        session = request.getCookie(SESSION_COOKIE_NAME)
        if session is None:
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
        )

        # Check for the state query parameter
        if b"state" not in request.args:
            self._render_error(request, "invalid_request", "State parameter is missing")
            return

        state = request.args[b"state"][0].decode()

        # Deserialize the session token and verify it.
        # FIXME: macaroon verification should be refactored somewhere else
        try:
            macaroon = pymacaroons.Macaroon.deserialize(session)
        except MacaroonDeserializationException as e:
            self._render_error(request, "invalid_session", str(e))
            return

        v = pymacaroons.Verifier()

        v.satisfy_exact("gen = 1")
        v.satisfy_exact("type = session")
        v.satisfy_exact("state = %s" % (state,))
        v.satisfy_general(self._verify_expiry)
        v.satisfy_general(lambda c: c.startswith("nonce = "))
        v.satisfy_general(lambda c: c.startswith("client_redirect_url = "))

        try:
            v.verify(macaroon, self._macaroon_secret_key)
        except Exception as e:
            self._render_error(request, "mismatching_session", str(e))
            return

        # Extract the `nonce` and `client_redirect_url` from the token
        nonce = self._get_value_from_macaroon(macaroon, "nonce")
        client_redirect_url = self._get_value_from_macaroon(
            macaroon, "client_redirect_url"
        )

        # Exchange the code with the provider
        if b"code" not in request.args:
            self._render_error(request, "invalid_request", "Code parameter is missing")
            return

        code = request.args[b"code"][0].decode()
        try:
            token = await self._exchange_code(code)
        except OidcError as e:
            self._render_error(request, e.error, e.error_description)
            return

        # Now that we have a token, get the userinfo, either by decoding the
        # `id_token` or by fetching the `userinfo_endpoint`.
        if self._uses_userinfo:
            try:
                userinfo = await self._fetch_userinfo(token)
            except Exception as e:
                self._render_error(request, "fetch_error", str(e))
                return
        else:
            try:
                userinfo = await self._parse_id_token(token, nonce=nonce)
            except Exception as e:
                self._render_error(request, "invalid_token", str(e))
                return

        # Call the mapper to register/login the user
        try:
            user_id = await self._map_userinfo_to_user(userinfo)
        except MappingException as e:
            self._render_error(request, "mapping_error", str(e))
            return

        # and finally complete the login
        self._auth_handler.complete_sso_login(user_id, request, client_redirect_url)

    def _get_value_from_macaroon(self, macaroon: pymacaroons.Macaroon, key: str):
        """Extracts a caveat value from a macaroon token.

        Args:
            macaroon (pymacaroons.Macaroon): the token
            key (str): the key of the caveat to extract

        Returns:
            str: the extracted value

        Raises:
            Exception: if the caveat was not in the macaroon
        """
        prefix = key + " = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(prefix):
                return caveat.caveat_id[len(prefix) :]
        raise Exception("No %s caveat in macaroon" % (key,))

    def _verify_expiry(self, caveat: str):
        prefix = "time < "
        if not caveat.startswith(prefix):
            return False
        expiry = int(caveat[len(prefix) :])
        now = self._clock.time_msec()
        return now < expiry

    async def _map_userinfo_to_user(self, userinfo: UserInfo) -> str:
        """Maps a UserInfo object to a mxid.

        UserInfo should have a claim that uniquely identifies users. This claim
        is usually `sub`, but can be configured with `oidc_config.subject_claim`.
        It is then used as an `external_id`.

        If we don't find the user that way, we should register the user,
        mapping the localpart and the display name from the UserInfo.

        If a user already exists with the mxid we've mapped, raise an exception.

        Args:
            userinfo (UserInfo): an object representing the user

        Raises:
            MappingException: if there was an error while mapping some properties

        Returns:
            str: the mxid of the user
        """
        try:
            remote_user_id = self._user_mapping_provider.get_remote_user_id(userinfo)
        except Exception as e:
            raise MappingException(
                "Failed to extract subject from OIDC response: %s" % (e,)
            )

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
            attributes = self._user_mapping_provider.map_user_attributes(userinfo)
        except Exception as e:
            raise MappingException(
                "Could not extract user attributes from OIDC response: %s"
                % (e.message,)
            )

        logger.debug(
            "Retrieved user attributes from user mapping provider: %r", attributes
        )

        if attributes["localpart"] == "":
            raise MappingException("localpart is empty")

        localpart = map_username_to_mxid_localpart(attributes["localpart"])

        user_id = UserID(localpart, self._hostname)
        if await self._datastore.get_users_by_id_case_insensitive(user_id.to_string()):
            # This mxid is taken
            raise MappingException(
                "mxid '{}' is already taken".format(user_id.to_string())
            )

        # It's the first time this user is logging in and the mapped mxid was
        # not taken, register the user
        registered_user_id = await self._registration_handler.register_user(
            localpart=localpart, default_display_name=attributes["display_name"],
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
        pass

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

    def map_user_attributes(self, userinfo: UserInfo) -> UserAttribute:
        """Map a ``UserInfo`` objects into user attributes.

        Args:
            userinfo: An object representing the user given by the OIDC provider

        Returns:
            A dict containing the ``localpart`` and (optionally) the ``display_name``
        """
        raise NotImplementedError()


# Used to clear out "None" values in templates
def jinja_finalize(thing):
    return thing if thing is not None else ""


env = Environment(finalize=jinja_finalize)

JinjaOidcMappingConfig = TypedDict(
    "JinjaOidcMappingConfig",
    {
        "subject_claim": str,
        "localpart_template": Template,
        "display_name_template": Optional[Template],
    },
)


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

        display_name_template: Optional[Template] = None
        if "display_name_template" in config:
            try:
                display_name_template = env.from_string(config["display_name_template"])
            except Exception as e:
                raise ConfigError(
                    "invalid jinja template for oidc_config.user_mapping_provider.config.display_name_template: %r"
                    % (e,)
                )

        return JinjaOidcMappingConfig(
            subject_claim=subject_claim,
            localpart_template=localpart_template,
            display_name_template=display_name_template,
        )

    def get_remote_user_id(self, userinfo: UserInfo) -> str:
        return userinfo[self._config["subject_claim"]]

    def map_user_attributes(self, userinfo: UserInfo) -> UserAttribute:
        localpart = self._config["localpart_template"].render(user=userinfo).strip()

        display_name: Optional[str] = None
        if self._config["display_name_template"] is not None:
            display_name = (
                self._config["display_name_template"].render(user=userinfo).strip()
            )

            if display_name == "":
                display_name = None

        return UserAttribute(localpart=localpart, display_name=display_name)
