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
from typing import Dict, List, Optional
from urllib.parse import parse_qsl

import pymacaroons
from authlib.common.security import generate_token
from authlib.jose import JsonWebToken
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oidc.core import CodeIDToken, ImplicitIDToken, UserInfo
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url
from jinja2 import Template
from pymacaroons.exceptions import MacaroonDeserializationException

from synapse.api.errors import HttpResponseException
from synapse.http.server import finish_request
from synapse.push.mailer import load_jinja2_templates
from synapse.types import UserID, map_username_to_mxid_localpart

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = b"oidc_session"


class OidcError(Exception):
    error = "unknown"
    error_description = None

    def __init__(self, error=None, error_description=None):
        self.error = error or self.error
        self.error_description = error_description or self.error_description


class MappingException(Exception):
    pass


class OidcHandler:
    def __init__(self, hs):
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
        self._mapping_templates = (
            hs.config.oidc_mapping_templates
        )  # type: Dict[str, Template]
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
    ):
        html_bytes = self._error_template.render(
            error=error, error_description=error_description
        ).encode("utf-8")

        request.setResponseCode(400)
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%i" % len(html_bytes))
        request.write(html_bytes)
        finish_request(request)

    def _validate_metadata(self):
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
        # Maybe that should be user-configurable and not infered?
        return "openid" not in self._scopes

    async def load_metadata(self) -> OpenIDProviderMetadata:
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

    async def _exchange_code(self, code: str) -> Dict[str, str]:
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

    async def _fetch_userinfo(self, token: Dict[str, str]) -> UserInfo:
        metadata = await self.load_metadata()

        resp = await self._http_client.get_json(
            metadata["userinfo_endpoint"],
            headers={"Authorization": ["Bearer {}".format(token["access_token"])]},
        )

        return UserInfo(resp)

    async def _parse_id_token(self, token: Dict[str, str], nonce: str) -> UserInfo:
        """Return an instance of UserInfo from token's ``id_token``."""
        metadata = await self.load_metadata()
        claims_params = {
            "nonce": nonce,
            "client_id": self._client_auth.client_id,
        }
        if "access_token" in token:
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

    async def handle_redirect_request(self, request, client_redirect_url: bytes) -> str:
        """Handle an incoming request to /login/sso/redirect

        Args:
            request (SynapseRequest)
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            str: URL to redirect to
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
        return prepare_grant_uri(
            authorization_endpoint,
            client_id=self._client_auth.client_id,
            response_type="code",
            redirect_uri=self._callback_url,
            scope=self._scopes,
            state=state,
            nonce=nonce,
        )

    async def handle_oidc_callback(self, request):
        """Handle an incoming request to /_synapse/oidc/callback

        Args:
            request (SynapseRequest): the incoming request from the browser. We'll
                respond to it with a redirect.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """

        if b"error" in request.args:
            error = request.args[b"error"][0].decode()
            description = request.args.get(b"error_description", [b""])[0].decode()
            self._render_error(request, error, description)
            return

        session = request.getCookie(SESSION_COOKIE_NAME)
        # Remove the cookie
        request.addCookie(
            SESSION_COOKIE_NAME,
            b"",
            path="/_synapse/oidc",
            expires="Thu, Jan 01 1970 00:00:00 UTC",
            httpOnly=True,
        )
        if session is None:
            self._render_error(request, "missing_session", "No session cookie found")
            return

        if b"state" not in request.args:
            self._render_error(request, "invalid_request", "State parameter is missing")
            return

        state = request.args[b"state"][0].decode()

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

        nonce = self._get_value_from_macaroon(macaroon, "nonce")
        client_redirect_url = self._get_value_from_macaroon(
            macaroon, "client_redirect_url"
        )

        if b"code" not in request.args:
            self._render_error(request, "invalid_request", "Code parameter is missing")
            return

        code = request.args[b"code"][0].decode()
        try:
            token = await self._exchange_code(code)
        except OidcError as e:
            self._render_error(request, e.error, e.error_description)
            return

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

        try:
            user_id = await self._map_userinfo_to_user(userinfo)
        except MappingException as e:
            self._render_error(request, "mapping_error", str(e))
            return

        self._auth_handler.complete_sso_login(user_id, request, client_redirect_url)

    def _get_value_from_macaroon(self, macaroon: pymacaroons.Macaroon, key: str):
        prefix = key + " = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(prefix):
                return caveat.caveat_id[len(prefix) :]
        raise MappingException("No %s caveat in macaroon" % (key,))

    def _verify_expiry(self, caveat: str):
        prefix = "time < "
        if not caveat.startswith(prefix):
            return False
        expiry = int(caveat[len(prefix) :])
        now = self._clock.time_msec()
        return now < expiry

    async def _map_userinfo_to_user(self, userinfo: UserInfo) -> str:
        remote_user_id = userinfo.get(self._subject_claim)
        if remote_user_id is None:
            raise MappingException("Failed to extract subject from OIDC response")

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

        # render the localpart template, raise if empty
        localpart = self._mapping_templates["localpart"].render(user=userinfo).strip()
        if localpart == "":
            raise MappingException("rendered localpart is empty")

        localpart = map_username_to_mxid_localpart(localpart)

        # render the display_name template, fallback to None
        displayname = (
            self._mapping_templates["display_name"].render(user=userinfo).strip()
        )  # Optional[str]
        if displayname == "":
            displayname = None

        user_id = UserID(localpart, self._hostname)
        if await self._datastore.get_users_by_id_case_insensitive(user_id.to_string()):
            # This mxid is taken
            raise MappingException(
                "mxid '{}' is already taken".format(user_id.to_string())
            )

        registered_user_id = await self._registration_handler.register_user(
            localpart=localpart, default_display_name=displayname,
        )

        await self._datastore.record_user_external_id(
            self._auth_provider_id, remote_user_id, registered_user_id,
        )
        return registered_user_id
