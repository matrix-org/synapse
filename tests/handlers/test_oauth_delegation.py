# Copyright 2022 Matrix.org Foundation C.I.C.
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

from http import HTTPStatus
from io import BytesIO
from typing import Any, Dict, Optional, Union
from unittest.mock import ANY, AsyncMock, Mock
from urllib.parse import parse_qs

from signedjson.key import (
    encode_verify_key_base64,
    generate_signing_key,
    get_verify_key,
)
from signedjson.sign import sign_json

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.http_headers import Headers
from twisted.web.iweb import IResponse

from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    OAuthInsufficientScopeError,
    SynapseError,
)
from synapse.http.site import SynapseRequest
from synapse.rest import admin
from synapse.rest.client import account, devices, keys, login, logout, register
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests.server import FakeChannel
from tests.test_utils import FakeResponse, get_awaitable_result
from tests.unittest import HomeserverTestCase, override_config, skip_unless
from tests.utils import HAS_AUTHLIB, checked_cast, mock_getRawHeaders

# These are a few constants that are used as config parameters in the tests.
SERVER_NAME = "test"
ISSUER = "https://issuer/"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
BASE_URL = "https://synapse/"
SCOPES = ["openid"]

AUTHORIZATION_ENDPOINT = ISSUER + "authorize"
TOKEN_ENDPOINT = ISSUER + "token"
USERINFO_ENDPOINT = ISSUER + "userinfo"
WELL_KNOWN = ISSUER + ".well-known/openid-configuration"
JWKS_URI = ISSUER + ".well-known/jwks.json"
INTROSPECTION_ENDPOINT = ISSUER + "introspect"

SYNAPSE_ADMIN_SCOPE = "urn:synapse:admin:*"
MATRIX_USER_SCOPE = "urn:matrix:org.matrix.msc2967.client:api:*"
MATRIX_GUEST_SCOPE = "urn:matrix:org.matrix.msc2967.client:api:guest"
MATRIX_DEVICE_SCOPE_PREFIX = "urn:matrix:org.matrix.msc2967.client:device:"
DEVICE = "AABBCCDD"
MATRIX_DEVICE_SCOPE = MATRIX_DEVICE_SCOPE_PREFIX + DEVICE
SUBJECT = "abc-def-ghi"
USERNAME = "test-user"
USER_ID = "@" + USERNAME + ":" + SERVER_NAME
OIDC_ADMIN_USERID = f"@__oidc_admin:{SERVER_NAME}"


async def get_json(url: str) -> JsonDict:
    # Mock get_json calls to handle jwks & oidc discovery endpoints
    if url == WELL_KNOWN:
        # Minimal discovery document, as defined in OpenID.Discovery
        # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        return {
            "issuer": ISSUER,
            "authorization_endpoint": AUTHORIZATION_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT,
            "jwks_uri": JWKS_URI,
            "userinfo_endpoint": USERINFO_ENDPOINT,
            "introspection_endpoint": INTROSPECTION_ENDPOINT,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
    elif url == JWKS_URI:
        return {"keys": []}

    return {}


@skip_unless(HAS_AUTHLIB, "requires authlib")
class MSC3861OAuthDelegation(HomeserverTestCase):
    servlets = [
        account.register_servlets,
        devices.register_servlets,
        keys.register_servlets,
        register.register_servlets,
        login.register_servlets,
        logout.register_servlets,
        admin.register_servlets,
    ]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        config["disable_registration"] = True
        config["experimental_features"] = {
            "msc3861": {
                "enabled": True,
                "issuer": ISSUER,
                "client_id": CLIENT_ID,
                "client_auth_method": "client_secret_post",
                "client_secret": CLIENT_SECRET,
                "admin_token": "admin_token_value",
            }
        }
        return config

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.http_client = Mock(spec=["get_json"])
        self.http_client.get_json.side_effect = get_json
        self.http_client.user_agent = b"Synapse Test"

        hs = self.setup_test_homeserver(proxied_http_client=self.http_client)

        # Import this here so that we've checked that authlib is available.
        from synapse.api.auth.msc3861_delegated import MSC3861DelegatedAuth

        self.auth = checked_cast(MSC3861DelegatedAuth, hs.get_auth())

        return hs

    def _assertParams(self) -> None:
        """Assert that the request parameters are correct."""
        params = parse_qs(self.http_client.request.call_args[1]["data"].decode("utf-8"))
        self.assertEqual(params["token"], ["mockAccessToken"])
        self.assertEqual(params["client_id"], [CLIENT_ID])
        self.assertEqual(params["client_secret"], [CLIENT_SECRET])

    def test_inactive_token(self) -> None:
        """The handler should return a 403 where the token is inactive."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={"active": False},
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), InvalidClientTokenError)
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()

    def test_active_no_scope(self) -> None:
        """The handler should return a 403 where no scope is given."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={"active": True},
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), InvalidClientTokenError)
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()

    def test_active_user_no_subject(self) -> None:
        """The handler should return a 500 when no subject is present."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={"active": True, "scope": " ".join([MATRIX_USER_SCOPE])},
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), InvalidClientTokenError)
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()

    def test_active_no_user_scope(self) -> None:
        """The handler should return a 500 when no subject is present."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([MATRIX_DEVICE_SCOPE]),
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), InvalidClientTokenError)
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()

    def test_active_admin_not_user(self) -> None:
        """The handler should raise when the scope has admin right but not user."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([SYNAPSE_ADMIN_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), InvalidClientTokenError)
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()

    def test_active_admin(self) -> None:
        """The handler should return a requester with admin rights."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([SYNAPSE_ADMIN_SCOPE, MATRIX_USER_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()
        self.assertEqual(requester.user.to_string(), "@%s:%s" % (USERNAME, SERVER_NAME))
        self.assertEqual(requester.is_guest, False)
        self.assertEqual(requester.device_id, None)
        self.assertEqual(
            get_awaitable_result(self.auth.is_server_admin(requester)), True
        )

    def test_active_admin_highest_privilege(self) -> None:
        """The handler should resolve to the most permissive scope."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join(
                        [SYNAPSE_ADMIN_SCOPE, MATRIX_USER_SCOPE, MATRIX_GUEST_SCOPE]
                    ),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()
        self.assertEqual(requester.user.to_string(), "@%s:%s" % (USERNAME, SERVER_NAME))
        self.assertEqual(requester.is_guest, False)
        self.assertEqual(requester.device_id, None)
        self.assertEqual(
            get_awaitable_result(self.auth.is_server_admin(requester)), True
        )

    def test_active_user(self) -> None:
        """The handler should return a requester with normal user rights."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([MATRIX_USER_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()
        self.assertEqual(requester.user.to_string(), "@%s:%s" % (USERNAME, SERVER_NAME))
        self.assertEqual(requester.is_guest, False)
        self.assertEqual(requester.device_id, None)
        self.assertEqual(
            get_awaitable_result(self.auth.is_server_admin(requester)), False
        )

    def test_active_user_with_device(self) -> None:
        """The handler should return a requester with normal user rights and a device ID."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([MATRIX_USER_SCOPE, MATRIX_DEVICE_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()
        self.assertEqual(requester.user.to_string(), "@%s:%s" % (USERNAME, SERVER_NAME))
        self.assertEqual(requester.is_guest, False)
        self.assertEqual(
            get_awaitable_result(self.auth.is_server_admin(requester)), False
        )
        self.assertEqual(requester.device_id, DEVICE)

    def test_multiple_devices(self) -> None:
        """The handler should raise an error if multiple devices are found in the scope."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join(
                        [
                            MATRIX_USER_SCOPE,
                            f"{MATRIX_DEVICE_SCOPE_PREFIX}AABBCC",
                            f"{MATRIX_DEVICE_SCOPE_PREFIX}DDEEFF",
                        ]
                    ),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), AuthError)

    def test_active_guest_not_allowed(self) -> None:
        """The handler should return an insufficient scope error."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([MATRIX_GUEST_SCOPE, MATRIX_DEVICE_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        error = self.get_failure(
            self.auth.get_user_by_req(request), OAuthInsufficientScopeError
        )
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()
        self.assertEqual(
            getattr(error.value, "headers", {})["WWW-Authenticate"],
            'Bearer error="insufficient_scope", scope="urn:matrix:org.matrix.msc2967.client:api:*"',
        )

    def test_active_guest_allowed(self) -> None:
        """The handler should return a requester with guest user rights and a device ID."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([MATRIX_GUEST_SCOPE, MATRIX_DEVICE_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(
            self.auth.get_user_by_req(request, allow_guest=True)
        )
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)
        self.http_client.request.assert_called_once_with(
            method="POST", uri=INTROSPECTION_ENDPOINT, data=ANY, headers=ANY
        )
        self._assertParams()
        self.assertEqual(requester.user.to_string(), "@%s:%s" % (USERNAME, SERVER_NAME))
        self.assertEqual(requester.is_guest, True)
        self.assertEqual(
            get_awaitable_result(self.auth.is_server_admin(requester)), False
        )
        self.assertEqual(requester.device_id, DEVICE)

    def test_unavailable_introspection_endpoint(self) -> None:
        """The handler should return an internal server error."""
        request = Mock(args={})
        request.args[b"access_token"] = [b"mockAccessToken"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()

        # The introspection endpoint is returning an error.
        self.http_client.request = AsyncMock(
            return_value=FakeResponse(code=500, body=b"Internal Server Error")
        )
        error = self.get_failure(self.auth.get_user_by_req(request), SynapseError)
        self.assertEqual(error.value.code, 503)

        # The introspection endpoint request fails.
        self.http_client.request = AsyncMock(side_effect=Exception())
        error = self.get_failure(self.auth.get_user_by_req(request), SynapseError)
        self.assertEqual(error.value.code, 503)

        # The introspection endpoint does not return a JSON object.
        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200, payload=["this is an array", "not an object"]
            )
        )
        error = self.get_failure(self.auth.get_user_by_req(request), SynapseError)
        self.assertEqual(error.value.code, 503)

        # The introspection endpoint does not return valid JSON.
        self.http_client.request = AsyncMock(
            return_value=FakeResponse(code=200, body=b"this is not valid JSON")
        )
        error = self.get_failure(self.auth.get_user_by_req(request), SynapseError)
        self.assertEqual(error.value.code, 503)

    def make_device_keys(self, user_id: str, device_id: str) -> JsonDict:
        # We only generate a master key to simplify the test.
        master_signing_key = generate_signing_key(device_id)
        master_verify_key = encode_verify_key_base64(get_verify_key(master_signing_key))

        return {
            "master_key": sign_json(
                {
                    "user_id": user_id,
                    "usage": ["master"],
                    "keys": {"ed25519:" + master_verify_key: master_verify_key},
                },
                user_id,
                master_signing_key,
            ),
        }

    def test_cross_signing(self) -> None:
        """Try uploading device keys with OAuth delegation enabled."""

        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(
                code=200,
                payload={
                    "active": True,
                    "sub": SUBJECT,
                    "scope": " ".join([MATRIX_USER_SCOPE, MATRIX_DEVICE_SCOPE]),
                    "username": USERNAME,
                },
            )
        )
        keys_upload_body = self.make_device_keys(USER_ID, DEVICE)
        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            keys_upload_body,
            access_token="mockAccessToken",
        )

        self.assertEqual(channel.code, 200, channel.json_body)

        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            keys_upload_body,
            access_token="mockAccessToken",
        )

        self.assertEqual(channel.code, HTTPStatus.NOT_IMPLEMENTED, channel.json_body)

    def expect_unauthorized(
        self, method: str, path: str, content: Union[bytes, str, JsonDict] = ""
    ) -> None:
        channel = self.make_request(method, path, content, shorthand=False)

        self.assertEqual(channel.code, 401, channel.json_body)

    def expect_unrecognized(
        self, method: str, path: str, content: Union[bytes, str, JsonDict] = ""
    ) -> None:
        channel = self.make_request(method, path, content)

        self.assertEqual(channel.code, 404, channel.json_body)
        self.assertEqual(
            channel.json_body["errcode"], Codes.UNRECOGNIZED, channel.json_body
        )

    def test_uia_endpoints(self) -> None:
        """Test that endpoints that were removed in MSC2964 are no longer available."""

        # This is just an endpoint that should remain visible (but requires auth):
        self.expect_unauthorized("GET", "/_matrix/client/v3/devices")

        # This remains usable, but will require a uia scope:
        self.expect_unauthorized(
            "POST", "/_matrix/client/v3/keys/device_signing/upload"
        )

    def test_3pid_endpoints(self) -> None:
        """Test that 3pid account management endpoints that were removed in MSC2964 are no longer available."""

        # Remains and requires auth:
        self.expect_unauthorized("GET", "/_matrix/client/v3/account/3pid")
        self.expect_unauthorized(
            "POST",
            "/_matrix/client/v3/account/3pid/bind",
            {
                "client_secret": "foo",
                "id_access_token": "bar",
                "id_server": "foo",
                "sid": "bar",
            },
        )
        self.expect_unauthorized("POST", "/_matrix/client/v3/account/3pid/unbind", {})

        # These are gone:
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/account/3pid"
        )  # deprecated
        self.expect_unrecognized("POST", "/_matrix/client/v3/account/3pid/add")
        self.expect_unrecognized("POST", "/_matrix/client/v3/account/3pid/delete")
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/account/3pid/email/requestToken"
        )
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/account/3pid/msisdn/requestToken"
        )

    def test_account_management_endpoints_removed(self) -> None:
        """Test that account management endpoints that were removed in MSC2964 are no longer available."""
        self.expect_unrecognized("POST", "/_matrix/client/v3/account/deactivate")
        self.expect_unrecognized("POST", "/_matrix/client/v3/account/password")
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/account/password/email/requestToken"
        )
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/account/password/msisdn/requestToken"
        )

    def test_registration_endpoints_removed(self) -> None:
        """Test that registration endpoints that were removed in MSC2964 are no longer available."""
        self.expect_unrecognized(
            "GET", "/_matrix/client/v1/register/m.login.registration_token/validity"
        )
        # This is still available for AS registrations
        # self.expect_unrecognized("POST", "/_matrix/client/v3/register")
        self.expect_unrecognized("GET", "/_matrix/client/v3/register/available")
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/register/email/requestToken"
        )
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/register/msisdn/requestToken"
        )

    def test_session_management_endpoints_removed(self) -> None:
        """Test that session management endpoints that were removed in MSC2964 are no longer available."""
        self.expect_unrecognized("GET", "/_matrix/client/v3/login")
        self.expect_unrecognized("POST", "/_matrix/client/v3/login")
        self.expect_unrecognized("GET", "/_matrix/client/v3/login/sso/redirect")
        self.expect_unrecognized("POST", "/_matrix/client/v3/logout")
        self.expect_unrecognized("POST", "/_matrix/client/v3/logout/all")
        self.expect_unrecognized("POST", "/_matrix/client/v3/refresh")
        self.expect_unrecognized("GET", "/_matrix/static/client/login")

    def test_device_management_endpoints_removed(self) -> None:
        """Test that device management endpoints that were removed in MSC2964 are no longer available."""
        self.expect_unrecognized("POST", "/_matrix/client/v3/delete_devices")
        self.expect_unrecognized("DELETE", "/_matrix/client/v3/devices/{DEVICE}")

    def test_openid_endpoints_removed(self) -> None:
        """Test that OpenID id_token endpoints that were removed in MSC2964 are no longer available."""
        self.expect_unrecognized(
            "POST", "/_matrix/client/v3/user/{USERNAME}/openid/request_token"
        )

    def test_admin_api_endpoints_removed(self) -> None:
        """Test that admin API endpoints that were removed in MSC2964 are no longer available."""
        self.expect_unrecognized("GET", "/_synapse/admin/v1/registration_tokens")
        self.expect_unrecognized("POST", "/_synapse/admin/v1/registration_tokens/new")
        self.expect_unrecognized("GET", "/_synapse/admin/v1/registration_tokens/abcd")
        self.expect_unrecognized("PUT", "/_synapse/admin/v1/registration_tokens/abcd")
        self.expect_unrecognized(
            "DELETE", "/_synapse/admin/v1/registration_tokens/abcd"
        )
        self.expect_unrecognized("POST", "/_synapse/admin/v1/reset_password/foo")
        self.expect_unrecognized("POST", "/_synapse/admin/v1/users/foo/login")
        self.expect_unrecognized("GET", "/_synapse/admin/v1/register")
        self.expect_unrecognized("POST", "/_synapse/admin/v1/register")
        self.expect_unrecognized("GET", "/_synapse/admin/v1/users/foo/admin")
        self.expect_unrecognized("PUT", "/_synapse/admin/v1/users/foo/admin")
        self.expect_unrecognized("POST", "/_synapse/admin/v1/account_validity/validity")

    def test_admin_token(self) -> None:
        """The handler should return a requester with admin rights when admin_token is used."""
        self.http_client.request = AsyncMock(
            return_value=FakeResponse.json(code=200, payload={"active": False}),
        )

        request = Mock(args={})
        request.args[b"access_token"] = [b"admin_token_value"]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(
            requester.user.to_string(),
            OIDC_ADMIN_USERID,
        )
        self.assertEqual(requester.is_guest, False)
        self.assertEqual(requester.device_id, None)
        self.assertEqual(
            get_awaitable_result(self.auth.is_server_admin(requester)), True
        )

        # There should be no call to the introspection endpoint
        self.http_client.request.assert_not_called()

    @override_config({"mau_stats_only": True})
    def test_request_tracking(self) -> None:
        """Using an access token should update the client_ips and MAU tables."""
        # To start, there are no MAU users.
        store = self.hs.get_datastores().main
        mau = self.get_success(store.get_monthly_active_count())
        self.assertEqual(mau, 0)

        known_token = "token-token-GOOD-:)"

        async def mock_http_client_request(
            method: str,
            uri: str,
            data: Optional[bytes] = None,
            headers: Optional[Headers] = None,
        ) -> IResponse:
            """Mocked auth provider response."""
            assert method == "POST"
            token = parse_qs(data)[b"token"][0].decode("utf-8")
            if token == known_token:
                return FakeResponse.json(
                    code=200,
                    payload={
                        "active": True,
                        "scope": MATRIX_USER_SCOPE,
                        "sub": SUBJECT,
                        "username": USERNAME,
                    },
                )

            return FakeResponse.json(code=200, payload={"active": False})

        self.http_client.request = mock_http_client_request

        EXAMPLE_IPV4_ADDR = "123.123.123.123"
        EXAMPLE_USER_AGENT = "httprettygood"

        # First test a known access token
        channel = FakeChannel(self.site, self.reactor)
        # type-ignore: FakeChannel is a mock of an HTTPChannel, not a proper HTTPChannel
        req = SynapseRequest(channel, self.site)  # type: ignore[arg-type]
        req.client.host = EXAMPLE_IPV4_ADDR
        req.requestHeaders.addRawHeader("Authorization", f"Bearer {known_token}")
        req.requestHeaders.addRawHeader("User-Agent", EXAMPLE_USER_AGENT)
        req.content = BytesIO(b"")
        req.requestReceived(
            b"GET",
            b"/_matrix/client/v3/account/whoami",
            b"1.1",
        )
        channel.await_result()
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        self.assertEqual(channel.json_body["user_id"], USER_ID, channel.json_body)

        # Expect to see one MAU entry, from the first request
        mau = self.get_success(store.get_monthly_active_count())
        self.assertEqual(mau, 1)

        conn_infos = self.get_success(
            store.get_user_ip_and_agents(UserID.from_string(USER_ID))
        )
        self.assertEqual(len(conn_infos), 1, conn_infos)
        conn_info = conn_infos[0]
        self.assertEqual(conn_info["access_token"], known_token)
        self.assertEqual(conn_info["ip"], EXAMPLE_IPV4_ADDR)
        self.assertEqual(conn_info["user_agent"], EXAMPLE_USER_AGENT)

        # Now test MAS making a request using the special __oidc_admin token
        MAS_IPV4_ADDR = "127.0.0.1"
        MAS_USER_AGENT = "masmasmas"

        channel = FakeChannel(self.site, self.reactor)
        req = SynapseRequest(channel, self.site)  # type: ignore[arg-type]
        req.client.host = MAS_IPV4_ADDR
        req.requestHeaders.addRawHeader(
            "Authorization", f"Bearer {self.auth._admin_token}"
        )
        req.requestHeaders.addRawHeader("User-Agent", MAS_USER_AGENT)
        req.content = BytesIO(b"")
        req.requestReceived(
            b"GET",
            b"/_matrix/client/v3/account/whoami",
            b"1.1",
        )
        channel.await_result()
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        self.assertEqual(
            channel.json_body["user_id"], OIDC_ADMIN_USERID, channel.json_body
        )

        # Still expect to see one MAU entry, from the first request
        mau = self.get_success(store.get_monthly_active_count())
        self.assertEqual(mau, 1)

        conn_infos = self.get_success(
            store.get_user_ip_and_agents(UserID.from_string(OIDC_ADMIN_USERID))
        )
        self.assertEqual(conn_infos, [])
