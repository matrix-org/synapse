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

import pymacaroons
from authlib.common.security import generate_token
from authlib.jose import JsonWebToken
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oidc.core import CodeIDToken, ImplicitIDToken, UserInfo
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url

from synapse.api.errors import SynapseError
from synapse.http.server import finish_request
from synapse.types import UserID, map_username_to_mxid_localpart

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = b"oidc_session"


class OidcHandler:
    def __init__(self, hs):
        self._callback_url = hs.config.oidc_callback_url
        self._scopes = hs.config.oidc_scopes
        self._client_auth = ClientAuth(
            hs.config.oidc_client_id, hs.config.oidc_client_secret
        )
        self._provider_metadata = OpenIDProviderMetadata(
            issuer=hs.config.oidc_issuer,
            authorization_endpoint=hs.config.oidc_authorization_endpoint,
            token_endpoint=hs.config.oidc_token_endpoint,
            userinfo_endpoint=hs.config.oidc_userinfo_endpoint,
            jwks_uri=hs.config.oidc_jwks_uri,
            response_type=hs.config.oidc_response_type,
        )
        self._provider_needs_discovery = hs.config.oidc_discover

        self._http_client = hs.get_proxied_http_client()
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()
        self._datastore = hs.get_datastore()
        self._macaroon_generator = hs.get_macaroon_generator()
        self._clock = hs.get_clock()
        self._hostname = hs.hostname
        self._macaroon_secret_key = hs.config.macaroon_secret_key

        # identifier for the external_ids table
        self._auth_provider_id = "oidc"

    def _validate_metadata(self):
        m = self._provider_metadata
        m.validate_issuer()
        m.validate_authorization_endpoint()
        m.validate_token_endpoint()

        if "response_types_supported" in m:
            m.validate_response_types_supported()

            if m["response_type"] not in m["response_types_supported"]:
                raise ValueError(
                    '%r not in "response_types_supported" (%r)'
                    % (self._response_type, m["response_types_supported"])
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
    def _uses_userinfo(self):
        return (
            "openid" not in self._scopes
            or self._provider_metadata["response_type"] == "access"
        )

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

    async def load_jwks(self):
        # FIXME: this should be periodically reloaded to support key rotation
        if self._uses_userinfo:
            # We're not using jwt signing, return an empty jwk set
            return []

        metadata = await self.load_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set:
            return jwk_set

        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        jwk_set = await self._http_client.get_json(uri)
        self._provider_metadata["jwks"] = jwk_set
        return jwk_set

    async def _exchange_code(self, code):
        metadata = await self.load_metadata()
        token_endpoint = metadata.get("token_endpoint")
        args = {
            "grant_type": "authorization_code",
            "code": code,
        }
        uri, headers, body = self._client_auth.prepare(
            method="POST", uri=token_endpoint, headers={}, body=""
        )
        headers = {k: [v] for (k, v) in headers.items()}
        resp = await self._http_client.post_urlencoded_get_json(
            uri, args, headers=headers
        )

        if "error" not in resp:
            return resp

        error = resp["error"]
        description = resp.get("error_description", error)
        raise SynapseError(400, "{}: {}".format(error, description))

    async def _parse_id_token(self, token, nonce):
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

        jwk_set = await self.load_jwks()
        claims = jwt.decode(
            token["id_token"],
            key=jwk_set,
            claims_cls=claims_cls,
            claims_options={"iss": {"values": [metadata["issuer"]]}},
            claims_params=claims_params,
        )

        claims.validate(leeway=120)  # allows 2 min of clock skew
        return UserInfo(claims)

    async def handle_redirect_request(self, request, client_redirect_url):
        """Handle an incoming request to /login/sso/redirect

        Args:
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            bytes: URL to redirect to
        """

        state = generate_token()
        nonce = generate_token()
        client_redirect_url = client_redirect_url.decode()

        cookie = self._macaroon_generator.generate_oidc_session_token(
            state=state, nonce=nonce, client_redirect_url=client_redirect_url,
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
        response_type = metadata.get("response_type", "code")
        return prepare_grant_uri(
            authorization_endpoint,
            client_id=self._client_auth.client_id,
            response_type=response_type,
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

        # TODO: show them nicely
        if b"error" in request.args:
            error = request.args[b"error"][0]
            description = request.args.get(b"error_description", [error])[0]
            raise SynapseError(400, "{}: {}".format(error, description))

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
            raise SynapseError(400, "No session cookie found")

        state = request.args[b"state"][0].decode()

        # FIXME: macaroon verification should be refactored somewhere else
        macaroon = pymacaroons.Macaroon.deserialize(session)

        v = pymacaroons.Verifier()

        v.satisfy_exact("gen = 1")
        v.satisfy_exact("type = session")
        v.satisfy_exact("state = %s" % (state,))
        v.satisfy_general(self._verify_expiry)
        v.satisfy_general(lambda c: c.startswith("nonce = "))
        v.satisfy_general(lambda c: c.startswith("client_redirect_url = "))

        v.verify(macaroon, self._macaroon_secret_key)

        nonce = self._get_value_from_macaroon(macaroon, "nonce")
        client_redirect_url = self._get_value_from_macaroon(
            macaroon, "client_redirect_url"
        )

        # TODO: support other flows?
        code = request.args[b"code"][0]
        token = await self._exchange_code(code)

        if "id_token" not in token:
            # TODO: fetch user infos using the userinfo endpoint when the id_token is not present
            raise SynapseError(400, "OP did not return id_token")

        userinfo = await self._parse_id_token(token, nonce=nonce)

        try:
            user_id = await self._map_userinfo_to_user(userinfo)
        except Exception as e:
            # If decoding the response or mapping it to a user failed, then log the
            # error and tell the user that something went wrong.
            logger.error(e)

            request.setResponseCode(400)
            request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
            request.setHeader(
                b"Content-Length", b"%d" % (len(self._error_html_content),)
            )
            request.write(self._error_html_content.encode("utf8"))
            finish_request(request)
            return

        self._auth_handler.complete_sso_login(user_id, request, client_redirect_url)

    def _get_value_from_macaroon(self, macaroon, key):
        prefix = key + " = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(prefix):
                return caveat.caveat_id[len(prefix) :]
        raise Exception("No %s caveat in macaroon" % (key,))

    def _verify_expiry(self, caveat):
        prefix = "time < "
        if not caveat.startswith(prefix):
            return False
        expiry = int(caveat[len(prefix) :])
        now = self._clock.time_msec()
        return now < expiry

    async def _map_userinfo_to_user(self, userinfo: UserInfo):
        remote_user_id = userinfo.get("sub")
        if remote_user_id is None:
            raise Exception("Failed to extract subject from OIDC response")

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

        # TODO: make those configurable
        localpart = userinfo.get("preferred_username")
        if localpart is None:
            raise Exception("No 'preferred_username' in ID token")

        localpart = map_username_to_mxid_localpart(localpart)
        displayname = userinfo.get("given_name")

        user_id = UserID(localpart, self._hostname)
        if await self._datastore.get_users_by_id_case_insensitive(user_id.to_string()):
            # This mxid is taken
            raise Exception("mxid '{}' is already taken".format(UserID.to_string()))

        registered_user_id = await self._registration_handler.register_user(
            localpart=localpart, default_display_name=displayname,
        )

        await self._datastore.record_user_external_id(
            self._auth_provider_id, remote_user_id, registered_user_id,
        )
        return registered_user_id
