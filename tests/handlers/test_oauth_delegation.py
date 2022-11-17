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
from typing import Any, Dict
from unittest.mock import ANY, Mock
from urllib.parse import parse_qs

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import InvalidClientTokenError, OAuthInsufficientScopeError
from synapse.rest.client import devices
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests.test_utils import FakeResponse, get_awaitable_result, simple_async_mock
from tests.unittest import HomeserverTestCase, skip_unless
from tests.utils import mock_getRawHeaders

try:
    import authlib  # noqa: F401

    HAS_AUTHLIB = True
except ImportError:
    HAS_AUTHLIB = False


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
DEVICE = "AABBCCDD"
MATRIX_DEVICE_SCOPE = "urn:matrix:org.matrix.msc2967.client:device:" + DEVICE
SUBJECT = "abc-def-ghi"
USERNAME = "test-user"


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
        devices.register_servlets,
    ]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        config["oauth_delegation"] = {
            "enabled": True,
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_auth_method": "client_secret_post",
            "client_secret": CLIENT_SECRET,
        }
        return config

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.http_client = Mock(spec=["get_json"])
        self.http_client.get_json.side_effect = get_json
        self.http_client.user_agent = b"Synapse Test"

        hs = self.setup_test_homeserver(proxied_http_client=self.http_client)

        self.auth = hs.get_auth()

        return hs

    def _assertParams(self) -> None:
        """Assert that the request parameters are correct."""
        params = parse_qs(self.http_client.request.call_args[1]["data"].decode("utf-8"))
        self.assertEqual(params["token"], ["mockAccessToken"])
        self.assertEqual(params["client_id"], [CLIENT_ID])
        self.assertEqual(params["client_secret"], [CLIENT_SECRET])

    def test_inactive_token(self) -> None:
        """The handler should return a 403 where the token is inactive."""

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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

    def test_active_admin(self) -> None:
        """The handler should return a requester with admin rights."""

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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

    def test_active_guest_not_allowed(self) -> None:
        """The handler should return an insufficient scope error."""

        self.http_client.request = simple_async_mock(
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

        self.http_client.request = simple_async_mock(
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
