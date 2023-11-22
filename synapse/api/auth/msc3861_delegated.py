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
from prometheus_client import Histogram

from twisted.web.client import readBody
from twisted.web.http_headers import Headers

from synapse.api.auth.base import BaseAuth
from synapse.api.errors import (
    AuthError,
    HttpResponseException,
    InvalidClientTokenError,
    OAuthInsufficientScopeError,
    StoreError,
    SynapseError,
)
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable
from synapse.types import Requester, UserID, create_requester
from synapse.util import json_decoder
from synapse.util.caches.cached_call import RetryOnExceptionCachedCall

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

introspection_response_timer = Histogram(
    "synapse_api_auth_delegated_introspection_response",
    "Time taken to get a response for an introspection request",
    ["code"],
)


# Scope as defined by MSC2967
# https://github.com/matrix-org/matrix-spec-proposals/pull/2967
SCOPE_MATRIX_API = "urn:matrix:org.matrix.msc2967.client:api:*"
SCOPE_MATRIX_GUEST = "urn:matrix:org.matrix.msc2967.client:api:guest"
SCOPE_MATRIX_DEVICE_PREFIX = "urn:matrix:org.matrix.msc2967.client:device:"

# Scope which allows access to the Synapse admin API
SCOPE_SYNAPSE_ADMIN = "urn:synapse:admin:*"


def scope_to_list(scope: str) -> List[str]:
    """Convert a scope string to a list of scope tokens"""
    return scope.strip().split(" ")


class PrivateKeyJWTWithKid(PrivateKeyJWT):  # type: ignore[misc]
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


class MSC3861DelegatedAuth(BaseAuth):
    AUTH_METHODS = {
        "client_secret_post": encode_client_secret_post,
        "client_secret_basic": encode_client_secret_basic,
        "client_secret_jwt": ClientSecretJWT(),
        "private_key_jwt": PrivateKeyJWTWithKid(),
    }

    EXTERNAL_ID_PROVIDER = "oauth-delegated"

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._config = hs.config.experimental.msc3861
        auth_method = MSC3861DelegatedAuth.AUTH_METHODS.get(
            self._config.client_auth_method.value, None
        )
        # Those assertions are already checked when parsing the config
        assert self._config.enabled, "OAuth delegation is not enabled"
        assert self._config.issuer, "No issuer provided"
        assert self._config.client_id, "No client_id provided"
        assert auth_method is not None, "Invalid client_auth_method provided"

        self._clock = hs.get_clock()
        self._http_client = hs.get_proxied_http_client()
        self._hostname = hs.hostname
        self._admin_token = self._config.admin_token

        self._issuer_metadata = RetryOnExceptionCachedCall(self._load_metadata)

        if isinstance(auth_method, PrivateKeyJWTWithKid):
            # Use the JWK as the client secret when using the private_key_jwt method
            assert self._config.jwk, "No JWK provided"
            self._client_auth = ClientAuth(
                self._config.client_id, self._config.jwk, auth_method
            )
        else:
            # Else use the client secret
            assert self._config.client_secret, "No client_secret provided"
            self._client_auth = ClientAuth(
                self._config.client_id, self._config.client_secret, auth_method
            )

    async def _load_metadata(self) -> OpenIDProviderMetadata:
        if self._config.issuer_metadata is not None:
            return OpenIDProviderMetadata(**self._config.issuer_metadata)
        url = get_well_known_url(self._config.issuer, external=True)
        response = await self._http_client.get_json(url)
        metadata = OpenIDProviderMetadata(**response)
        # metadata.validate_introspection_endpoint()
        return metadata

    async def _introspect_token(self, token: str) -> IntrospectionToken:
        """
        Send a token to the introspection endpoint and returns the introspection response

        Parameters:
            token: The token to introspect

        Raises:
            HttpResponseException: If the introspection endpoint returns a non-2xx response
            ValueError: If the introspection endpoint returns an invalid JSON response
            JSONDecodeError: If the introspection endpoint returns a non-JSON response
            Exception: If the HTTP request fails

        Returns:
            The introspection response
        """
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
        # check the HTTP status code, and we do the body encoding ourselves.

        start_time = self._clock.time()
        try:
            response = await self._http_client.request(
                method="POST",
                uri=uri,
                data=body.encode("utf-8"),
                headers=headers,
            )

            resp_body = await make_deferred_yieldable(readBody(response))
        except Exception:
            end_time = self._clock.time()
            introspection_response_timer.labels("ERR").observe(end_time - start_time)
            raise

        end_time = self._clock.time()
        introspection_response_timer.labels(response.code).observe(
            end_time - start_time
        )

        if response.code < 200 or response.code >= 300:
            raise HttpResponseException(
                response.code,
                response.phrase.decode("ascii", errors="replace"),
                resp_body,
            )

        resp = json_decoder.decode(resp_body.decode("utf-8"))

        if not isinstance(resp, dict):
            raise ValueError(
                "The introspection endpoint returned an invalid JSON response."
            )

        return IntrospectionToken(**resp)

    async def is_server_admin(self, requester: Requester) -> bool:
        return "urn:synapse:admin:*" in requester.scope

    async def get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool = False,
        allow_expired: bool = False,
        allow_locked: bool = False,
    ) -> Requester:
        access_token = self.get_access_token_from_request(request)

        requester = await self.get_appservice_user(request, access_token)
        if not requester:
            # TODO: we probably want to assert the allow_guest inside this call
            # so that we don't provision the user if they don't have enough permission:
            requester = await self.get_user_by_access_token(access_token, allow_expired)

        # Do not record requests from MAS using the virtual `__oidc_admin` user.
        if access_token != self._admin_token:
            await self._record_request(request, requester)

        if not allow_guest and requester.is_guest:
            raise OAuthInsufficientScopeError([SCOPE_MATRIX_API])

        request.requester = requester

        return requester

    async def get_user_by_access_token(
        self,
        token: str,
        allow_expired: bool = False,
    ) -> Requester:
        if self._admin_token is not None and token == self._admin_token:
            # XXX: This is a temporary solution so that the admin API can be called by
            # the OIDC provider. This will be removed once we have OIDC client
            # credentials grant support in matrix-authentication-service.
            logging.info("Admin toked used")
            # XXX: that user doesn't exist and won't be provisioned.
            # This is mostly fine for admin calls, but we should also think about doing
            # requesters without a user_id.
            admin_user = UserID("__oidc_admin", self._hostname)
            return create_requester(
                user_id=admin_user,
                scope=["urn:synapse:admin:*"],
            )

        try:
            introspection_result = await self._introspect_token(token)
        except Exception:
            logger.exception("Failed to introspect token")
            raise SynapseError(503, "Unable to introspect the access token")

        logger.info(f"Introspection result: {introspection_result!r}")

        # TODO: introspection verification should be more extensive, especially:
        #   - verify the audience
        if not introspection_result.get("active"):
            raise InvalidClientTokenError("Token is not active")

        # Let's look at the scope
        scope: List[str] = scope_to_list(introspection_result.get("scope", ""))

        # Determine type of user based on presence of particular scopes
        has_user_scope = SCOPE_MATRIX_API in scope
        has_guest_scope = SCOPE_MATRIX_GUEST in scope

        if not has_user_scope and not has_guest_scope:
            raise InvalidClientTokenError("No scope in token granting user rights")

        # Match via the sub claim
        sub: Optional[str] = introspection_result.get("sub")
        if sub is None:
            raise InvalidClientTokenError(
                "Invalid sub claim in the introspection result"
            )

        user_id_str = await self.store.get_user_by_external_id(
            MSC3861DelegatedAuth.EXTERNAL_ID_PROVIDER, sub
        )
        if user_id_str is None:
            # If we could not find a user via the external_id, it either does not exist,
            # or the external_id was never recorded

            # TODO: claim mapping should be configurable
            username: Optional[str] = introspection_result.get("username")
            if username is None or not isinstance(username, str):
                raise AuthError(
                    500,
                    "Invalid username claim in the introspection result",
                )
            user_id = UserID(username, self._hostname)

            # First try to find a user from the username claim
            user_info = await self.store.get_user_by_id(user_id=user_id.to_string())
            if user_info is None:
                # If the user does not exist, we should create it on the fly
                # TODO: we could use SCIM to provision users ahead of time and listen
                # for SCIM SET events if those ever become standard:
                # https://datatracker.ietf.org/doc/html/draft-hunt-scim-notify-00

                # TODO: claim mapping should be configurable
                # If present, use the name claim as the displayname
                name: Optional[str] = introspection_result.get("name")

                await self.store.register_user(
                    user_id=user_id.to_string(), create_profile_with_displayname=name
                )

            # And record the sub as external_id
            await self.store.record_user_external_id(
                MSC3861DelegatedAuth.EXTERNAL_ID_PROVIDER, sub, user_id.to_string()
            )
        else:
            user_id = UserID.from_string(user_id_str)

        # Find device_ids in scope
        # We only allow a single device_id in the scope, so we find them all in the
        # scope list, and raise if there are more than one. The OIDC server should be
        # the one enforcing valid scopes, so we raise a 500 if we find an invalid scope.
        device_ids = [
            tok[len(SCOPE_MATRIX_DEVICE_PREFIX) :]
            for tok in scope
            if tok.startswith(SCOPE_MATRIX_DEVICE_PREFIX)
        ]

        if len(device_ids) > 1:
            raise AuthError(
                500,
                "Multiple device IDs in scope",
            )

        device_id = device_ids[0] if device_ids else None
        if device_id is not None:
            # Sanity check the device_id
            if len(device_id) > 255 or len(device_id) < 1:
                raise AuthError(
                    500,
                    "Invalid device ID in scope",
                )

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
            is_guest=(has_guest_scope and not has_user_scope),
        )
