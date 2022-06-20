# Copyright 2023 The Matrix.org Foundation.
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
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import urlencode

from authlib.oauth2 import ClientAuth
from authlib.oauth2.auth import encode_client_secret_basic, encode_client_secret_post
from authlib.oauth2.rfc7523 import ClientSecretJWT, PrivateKeyJWT, private_key_jwt_sign
from authlib.oauth2.rfc7662 import IntrospectionToken
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url

from twisted.web.client import readBody
from twisted.web.http_headers import Headers

from synapse.api.auth.base import BaseAuth
from synapse.api.errors import AuthError, StoreError
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable
from synapse.types import Requester, UserID, create_requester
from synapse.util import json_decoder
from synapse.util.caches.cached_call import RetryOnExceptionCachedCall

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def scope_to_list(scope: str) -> List[str]:
    """Convert a scope string to a list of scope tokens"""
    return scope.strip().split(" ")


class PrivateKeyJWTWithKid(PrivateKeyJWT):
    """An implementation of the private_key_jwt client auth method that includes a kid header.

    This is needed because some providers (Keycloak) require the kid header to figure
    out which key to use to verify the signature.
    """

    def sign(self, auth: Any, token_endpoint: str) -> bytes:
        return private_key_jwt_sign(
            auth.client_secret,
            client_id=auth.client_id,
            token_endpoint=token_endpoint,
            claims=self.claims,
            header={"kid": auth.client_secret["kid"]},
        )


class OAuthDelegatedAuth(BaseAuth):
    AUTH_METHODS = {
        "client_secret_post": encode_client_secret_post,
        "client_secret_basic": encode_client_secret_basic,
        "client_secret_jwt": ClientSecretJWT(),
        "private_key_jwt": PrivateKeyJWTWithKid(),
    }

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._config = hs.config.auth
        assert self._config.oauth_delegation_enabled, "OAuth delegation is not enabled"
        assert self._config.oauth_delegation_issuer, "No issuer provided"
        assert self._config.oauth_delegation_client_id, "No client_id provided"
        assert self._config.oauth_delegation_client_secret, "No client_secret provided"
        assert (
            self._config.oauth_delegation_client_auth_method
            in OAuthDelegatedAuth.AUTH_METHODS
        ), "Invalid client_auth_method"

        self._http_client = hs.get_proxied_http_client()
        self._hostname = hs.hostname

        self._issuer_metadata = RetryOnExceptionCachedCall(self._load_metadata)
        secret = self._config.oauth_delegation_client_secret
        self._client_auth = ClientAuth(
            self._config.oauth_delegation_client_id,
            secret,
            OAuthDelegatedAuth.AUTH_METHODS[
                self._config.oauth_delegation_client_auth_method
            ],
        )

    async def _load_metadata(self) -> OpenIDProviderMetadata:
        if self._config.oauth_delegation_issuer_metadata is not None:
            return OpenIDProviderMetadata(
                **self._config.oauth_delegation_issuer_metadata
            )
        url = get_well_known_url(self._config.oauth_delegation_issuer, external=True)
        response = await self._http_client.get_json(url)
        metadata = OpenIDProviderMetadata(**response)
        # metadata.validate_introspection_endpoint()
        return metadata

    async def _introspect_token(self, token: str) -> IntrospectionToken:
        metadata = await self._issuer_metadata.get()
        introspection_endpoint = metadata.get("introspection_endpoint")
        raw_headers: Dict[str, str] = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": str(self._http_client.user_agent, "utf-8"),
            "Accept": "application/json",
        }

        args = {"token": token, "token_type_hint": "access_token"}
        body = urlencode(args, True)

        # Fill the body/headers with credentials
        uri, raw_headers, body = self._client_auth.prepare(
            method="POST", uri=introspection_endpoint, headers=raw_headers, body=body
        )
        headers = Headers({k: [v] for (k, v) in raw_headers.items()})

        # Do the actual request
        # We're not using the SimpleHttpClient util methods as we don't want to
        # check the HTTP status code and we do the body encoding ourself.
        response = await self._http_client.request(
            method="POST",
            uri=uri,
            data=body.encode("utf-8"),
            headers=headers,
        )

        resp_body = await make_deferred_yieldable(readBody(response))
        # TODO: Let's not worry about 5xx errors & co. for now and just try
        # decoding that as JSON. We should also do some validation of the
        # response
        resp = json_decoder.decode(resp_body.decode("utf-8"))
        return IntrospectionToken(**resp)

    async def is_server_admin(self, requester: Requester) -> bool:
        return "urn:synapse:admin:*" in requester.scope

    async def get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool = False,
        allow_expired: bool = False,
    ) -> Requester:
        access_token = self.get_access_token_from_request(request)
        return await self.get_user_by_access_token(access_token, allow_expired)

    async def get_user_by_access_token(
        self,
        token: str,
        allow_expired: bool = False,
    ) -> Requester:
        introspection_result = await self._introspect_token(token)

        logger.info(f"Introspection result: {introspection_result!r}")

        # TODO: introspection verification should be more extensive, especially:
        #   - verify the scopes
        #   - verify the audience
        if not introspection_result.get("active"):
            raise AuthError(
                403,
                "Invalid access token",
            )

        # TODO: claim mapping should be configurable
        username: Optional[str] = introspection_result.get("username")
        if username is None or not isinstance(username, str):
            raise AuthError(
                500,
                "Invalid username claim in the introspection result",
            )

        # Let's look at the scope
        scope: List[str] = scope_to_list(introspection_result.get("scope", ""))
        device_id = None
        # Find device_id in scope
        for tok in scope:
            if tok.startswith("urn:matrix:org.matrix.msc2967.client:device:"):
                parts = tok.split(":")
                if len(parts) == 5:
                    device_id = parts[4]

        user_id = UserID(username, self._hostname)
        user_info = await self.store.get_userinfo_by_id(user_id=user_id.to_string())

        # If the user does not exist, we should create it on the fly
        # TODO: we could use SCIM to provision users ahead of time and listen
        # for SCIM SET events if those ever become standard:
        # https://datatracker.ietf.org/doc/html/draft-hunt-scim-notify-00
        if not user_info:
            await self.store.register_user(user_id=user_id.to_string())
            user_info = await self.store.get_userinfo_by_id(user_id=user_id.to_string())
            if not user_info:
                raise AuthError(
                    500,
                    "Could not create user on the fly",
                )

        if device_id:
            # Create the device on the fly if it does not exist
            try:
                await self.store.get_device(
                    user_id=user_id.to_string(), device_id=device_id
                )
            except StoreError:
                await self.store.store_device(
                    user_id=user_id.to_string(),
                    device_id=device_id,
                    initial_device_display_name="OIDC-native client",
                )

        # TODO: there is a few things missing in the requester here, which still need
        # to be figured out, like:
        #   - impersonation, with the `authenticated_entity`, which is used for
        #     rate-limiting, MAU limits, etc.
        #   - shadow-banning, with the `shadow_banned` flag
        #   - a proper solution for appservices, which still needs to be figured out in
        #     the context of MSC3861
        return create_requester(
            user_id=user_id,
            device_id=device_id,
            scope=scope,
        )
