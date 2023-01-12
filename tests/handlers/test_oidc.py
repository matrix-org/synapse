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
import os
from typing import Any, Dict, Tuple
from unittest.mock import ANY, Mock, patch
from urllib.parse import parse_qs, urlparse

import pymacaroons

from twisted.test.proto_helpers import MemoryReactor

from synapse.handlers.sso import MappingException
from synapse.http.site import SynapseRequest
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util import Clock
from synapse.util.macaroons import get_value_from_macaroon
from synapse.util.stringutils import random_string

from tests.test_utils import FakeResponse, get_awaitable_result, simple_async_mock
from tests.test_utils.oidc import FakeAuthorizationGrant, FakeOidcServer
from tests.unittest import HomeserverTestCase, override_config

try:
    import authlib  # noqa: F401

    HAS_OIDC = True
except ImportError:
    HAS_OIDC = False


# These are a few constants that are used as config parameters in the tests.
ISSUER = "https://issuer/"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
BASE_URL = "https://synapse/"
CALLBACK_URL = BASE_URL + "_synapse/client/oidc/callback"
SCOPES = ["openid"]

# config for common cases
DEFAULT_CONFIG = {
    "enabled": True,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "issuer": ISSUER,
    "scopes": SCOPES,
    "user_mapping_provider": {"module": __name__ + ".TestMappingProvider"},
}

# extends the default config with explicit OAuth2 endpoints instead of using discovery
EXPLICIT_ENDPOINT_CONFIG = {
    **DEFAULT_CONFIG,
    "discover": False,
    "authorization_endpoint": ISSUER + "authorize",
    "token_endpoint": ISSUER + "token",
    "jwks_uri": ISSUER + "jwks",
}


class TestMappingProvider:
    @staticmethod
    def parse_config(config):
        return

    def __init__(self, config):
        pass

    def get_remote_user_id(self, userinfo):
        return userinfo["sub"]

    async def map_user_attributes(self, userinfo, token):
        return {"localpart": userinfo["username"], "display_name": None}

    # Do not include get_extra_attributes to test backwards compatibility paths.


class TestMappingProviderExtra(TestMappingProvider):
    async def get_extra_attributes(self, userinfo, token):
        return {"phone": userinfo["phone"]}


class TestMappingProviderFailures(TestMappingProvider):
    async def map_user_attributes(self, userinfo, token, failures):
        return {
            "localpart": userinfo["username"] + (str(failures) if failures else ""),
            "display_name": None,
        }


def _key_file_path() -> str:
    """path to a file containing the private half of a test key"""

    # this key was generated with:
    #   openssl ecparam -name prime256v1 -genkey -noout |
    #       openssl pkcs8 -topk8 -nocrypt -out oidc_test_key.p8
    #
    # we use PKCS8 rather than SEC-1 (which is what openssl ecparam spits out), because
    # that's what Apple use, and we want to be sure that we work with Apple's keys.
    #
    # (For the record: both PKCS8 and SEC-1 specify (different) ways of representing
    # keys using ASN.1. Both are then typically formatted using PEM, which says: use the
    # base64-encoded DER encoding of ASN.1, with headers and footers. But we don't
    # really need to care about any of that.)
    return os.path.join(os.path.dirname(__file__), "oidc_test_key.p8")


def _public_key_file_path() -> str:
    """path to a file containing the public half of a test key"""
    # this was generated with:
    #    openssl ec -in oidc_test_key.p8 -pubout -out oidc_test_key.pub.pem
    #
    # See above about where oidc_test_key.p8 came from
    return os.path.join(os.path.dirname(__file__), "oidc_test_key.pub.pem")


class OidcHandlerTestCase(HomeserverTestCase):
    if not HAS_OIDC:
        skip = "requires OIDC"

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        return config

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.fake_server = FakeOidcServer(clock=clock, issuer=ISSUER)

        hs = self.setup_test_homeserver()
        self.hs_patcher = self.fake_server.patch_homeserver(hs=hs)
        self.hs_patcher.start()

        self.handler = hs.get_oidc_handler()
        self.provider = self.handler._providers["oidc"]
        sso_handler = hs.get_sso_handler()
        # Mock the render error method.
        self.render_error = Mock(return_value=None)
        sso_handler.render_error = self.render_error  # type: ignore[assignment]

        # Reduce the number of attempts when generating MXIDs.
        sso_handler._MAP_USERNAME_RETRIES = 3

        auth_handler = hs.get_auth_handler()
        # Mock the complete SSO login method.
        self.complete_sso_login = simple_async_mock()
        auth_handler.complete_sso_login = self.complete_sso_login  # type: ignore[assignment]

        return hs

    def tearDown(self) -> None:
        self.hs_patcher.stop()
        return super().tearDown()

    def reset_mocks(self):
        """Reset all the Mocks."""
        self.fake_server.reset_mocks()
        self.render_error.reset_mock()
        self.complete_sso_login.reset_mock()

    def metadata_edit(self, values):
        """Modify the result that will be returned by the well-known query"""

        metadata = self.fake_server.get_metadata()
        metadata.update(values)
        return patch.object(self.fake_server, "get_metadata", return_value=metadata)

    def start_authorization(
        self,
        userinfo: dict,
        client_redirect_url: str = "http://client/redirect",
        scope: str = "openid",
        with_sid: bool = False,
    ) -> Tuple[SynapseRequest, FakeAuthorizationGrant]:
        """Start an authorization request, and get the callback request back."""
        nonce = random_string(10)
        state = random_string(10)

        code, grant = self.fake_server.start_authorization(
            userinfo=userinfo,
            scope=scope,
            client_id=self.provider._client_auth.client_id,
            redirect_uri=self.provider._callback_url,
            nonce=nonce,
            with_sid=with_sid,
        )
        session = self._generate_oidc_session_token(state, nonce, client_redirect_url)
        return _build_callback_request(code, state, session), grant

    def assertRenderedError(self, error, error_description=None):
        self.render_error.assert_called_once()
        args = self.render_error.call_args[0]
        self.assertEqual(args[1], error)
        if error_description is not None:
            self.assertEqual(args[2], error_description)
        # Reset the render_error mock
        self.render_error.reset_mock()
        return args

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_config(self) -> None:
        """Basic config correctly sets up the callback URL and client auth correctly."""
        self.assertEqual(self.provider._callback_url, CALLBACK_URL)
        self.assertEqual(self.provider._client_auth.client_id, CLIENT_ID)
        self.assertEqual(self.provider._client_auth.client_secret, CLIENT_SECRET)

    @override_config({"oidc_config": {**DEFAULT_CONFIG, "discover": True}})
    def test_discovery(self) -> None:
        """The handler should discover the endpoints from OIDC discovery document."""
        # This would throw if some metadata were invalid
        metadata = self.get_success(self.provider.load_metadata())
        self.fake_server.get_metadata_handler.assert_called_once()

        self.assertEqual(metadata.issuer, self.fake_server.issuer)
        self.assertEqual(
            metadata.authorization_endpoint,
            self.fake_server.authorization_endpoint,
        )
        self.assertEqual(metadata.token_endpoint, self.fake_server.token_endpoint)
        self.assertEqual(metadata.jwks_uri, self.fake_server.jwks_uri)
        # It seems like authlib does not have that defined in its metadata models
        self.assertEqual(
            metadata.get("userinfo_endpoint"),
            self.fake_server.userinfo_endpoint,
        )

        # subsequent calls should be cached
        self.reset_mocks()
        self.get_success(self.provider.load_metadata())
        self.fake_server.get_metadata_handler.assert_not_called()

    @override_config({"oidc_config": EXPLICIT_ENDPOINT_CONFIG})
    def test_no_discovery(self) -> None:
        """When discovery is disabled, it should not try to load from discovery document."""
        self.get_success(self.provider.load_metadata())
        self.fake_server.get_metadata_handler.assert_not_called()

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_load_jwks(self) -> None:
        """JWKS loading is done once (then cached) if used."""
        jwks = self.get_success(self.provider.load_jwks())
        self.fake_server.get_jwks_handler.assert_called_once()
        self.assertEqual(jwks, self.fake_server.get_jwks())

        # subsequent calls should be cached…
        self.reset_mocks()
        self.get_success(self.provider.load_jwks())
        self.fake_server.get_jwks_handler.assert_not_called()

        # …unless forced
        self.reset_mocks()
        self.get_success(self.provider.load_jwks(force=True))
        self.fake_server.get_jwks_handler.assert_called_once()

        with self.metadata_edit({"jwks_uri": None}):
            # If we don't do this, the load_metadata call will throw because of the
            # missing jwks_uri
            self.provider._user_profile_method = "userinfo_endpoint"
            self.get_success(self.provider.load_metadata(force=True))
            self.get_failure(self.provider.load_jwks(force=True), RuntimeError)

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_validate_config(self) -> None:
        """Provider metadatas are extensively validated."""
        h = self.provider

        def force_load_metadata():
            async def force_load():
                return await h.load_metadata(force=True)

            return get_awaitable_result(force_load())

        # Default test config does not throw
        force_load_metadata()

        with self.metadata_edit({"issuer": None}):
            self.assertRaisesRegex(ValueError, "issuer", force_load_metadata)

        with self.metadata_edit({"issuer": "http://insecure/"}):
            self.assertRaisesRegex(ValueError, "issuer", force_load_metadata)

        with self.metadata_edit({"issuer": "https://invalid/?because=query"}):
            self.assertRaisesRegex(ValueError, "issuer", force_load_metadata)

        with self.metadata_edit({"authorization_endpoint": None}):
            self.assertRaisesRegex(
                ValueError, "authorization_endpoint", force_load_metadata
            )

        with self.metadata_edit({"authorization_endpoint": "http://insecure/auth"}):
            self.assertRaisesRegex(
                ValueError, "authorization_endpoint", force_load_metadata
            )

        with self.metadata_edit({"token_endpoint": None}):
            self.assertRaisesRegex(ValueError, "token_endpoint", force_load_metadata)

        with self.metadata_edit({"token_endpoint": "http://insecure/token"}):
            self.assertRaisesRegex(ValueError, "token_endpoint", force_load_metadata)

        with self.metadata_edit({"jwks_uri": None}):
            self.assertRaisesRegex(ValueError, "jwks_uri", force_load_metadata)

        with self.metadata_edit({"jwks_uri": "http://insecure/jwks.json"}):
            self.assertRaisesRegex(ValueError, "jwks_uri", force_load_metadata)

        with self.metadata_edit({"response_types_supported": ["id_token"]}):
            self.assertRaisesRegex(
                ValueError, "response_types_supported", force_load_metadata
            )

        with self.metadata_edit(
            {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        ):
            # should not throw, as client_secret_basic is the default auth method
            force_load_metadata()

        with self.metadata_edit(
            {"token_endpoint_auth_methods_supported": ["client_secret_post"]}
        ):
            self.assertRaisesRegex(
                ValueError,
                "token_endpoint_auth_methods_supported",
                force_load_metadata,
            )

        # Tests for configs that require the userinfo endpoint
        self.assertFalse(h._uses_userinfo)
        self.assertEqual(h._user_profile_method, "auto")
        h._user_profile_method = "userinfo_endpoint"
        self.assertTrue(h._uses_userinfo)

        # Revert the profile method and do not request the "openid" scope: this should
        # mean that we check for a userinfo endpoint
        h._user_profile_method = "auto"
        h._scopes = []
        self.assertTrue(h._uses_userinfo)
        with self.metadata_edit({"userinfo_endpoint": None}):
            self.assertRaisesRegex(ValueError, "userinfo_endpoint", force_load_metadata)

        with self.metadata_edit({"jwks_uri": None}):
            # Shouldn't raise with a valid userinfo, even without jwks
            force_load_metadata()

    @override_config({"oidc_config": {**DEFAULT_CONFIG, "skip_verification": True}})
    def test_skip_verification(self) -> None:
        """Provider metadata validation can be disabled by config."""
        with self.metadata_edit({"issuer": "http://insecure"}):
            # This should not throw
            get_awaitable_result(self.provider.load_metadata())

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_redirect_request(self) -> None:
        """The redirect request has the right arguments & generates a valid session cookie."""
        req = Mock(spec=["cookies"])
        req.cookies = []

        url = urlparse(
            self.get_success(
                self.provider.handle_redirect_request(req, b"http://client/redirect")
            )
        )
        auth_endpoint = urlparse(self.fake_server.authorization_endpoint)

        self.assertEqual(url.scheme, auth_endpoint.scheme)
        self.assertEqual(url.netloc, auth_endpoint.netloc)
        self.assertEqual(url.path, auth_endpoint.path)

        params = parse_qs(url.query)
        self.assertEqual(params["redirect_uri"], [CALLBACK_URL])
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["scope"], [" ".join(SCOPES)])
        self.assertEqual(params["client_id"], [CLIENT_ID])
        self.assertEqual(len(params["state"]), 1)
        self.assertEqual(len(params["nonce"]), 1)

        # Check what is in the cookies
        self.assertEqual(len(req.cookies), 2)  # two cookies
        cookie_header = req.cookies[0]

        # The cookie name and path don't really matter, just that it has to be coherent
        # between the callback & redirect handlers.
        parts = [p.strip() for p in cookie_header.split(b";")]
        self.assertIn(b"Path=/_synapse/client/oidc", parts)
        name, cookie = parts[0].split(b"=")
        self.assertEqual(name, b"oidc_session")

        macaroon = pymacaroons.Macaroon.deserialize(cookie)
        state = get_value_from_macaroon(macaroon, "state")
        nonce = get_value_from_macaroon(macaroon, "nonce")
        redirect = get_value_from_macaroon(macaroon, "client_redirect_url")

        self.assertEqual(params["state"], [state])
        self.assertEqual(params["nonce"], [nonce])
        self.assertEqual(redirect, "http://client/redirect")

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_callback_error(self) -> None:
        """Errors from the provider returned in the callback are displayed."""
        request = Mock(args={})
        request.args[b"error"] = [b"invalid_client"]
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_client", "")

        request.args[b"error_description"] = [b"some description"]
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_client", "some description")

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_callback(self) -> None:
        """Code callback works and display errors if something went wrong.

        A lot of scenarios are tested here:
         - when the callback works, with userinfo from ID token
         - when the user mapping fails
         - when ID token verification fails
         - when the callback works, with userinfo fetched from the userinfo endpoint
         - when the userinfo fetching fails
         - when the code exchange fails
        """

        # ensure that we are correctly testing the fallback when "get_extra_attributes"
        # is not implemented.
        mapping_provider = self.provider._user_mapping_provider
        with self.assertRaises(AttributeError):
            _ = mapping_provider.get_extra_attributes

        username = "bar"
        userinfo = {
            "sub": "foo",
            "username": username,
        }
        expected_user_id = "@%s:%s" % (username, self.hs.hostname)

        client_redirect_url = "http://client/redirect"
        request, _ = self.start_authorization(
            userinfo, client_redirect_url=client_redirect_url
        )
        self.get_success(self.handler.handle_oidc_callback(request))

        self.complete_sso_login.assert_called_once_with(
            expected_user_id,
            self.provider.idp_id,
            request,
            client_redirect_url,
            None,
            new_user=True,
            auth_provider_session_id=None,
        )
        self.fake_server.post_token_handler.assert_called_once()
        self.fake_server.get_userinfo_handler.assert_not_called()
        self.render_error.assert_not_called()

        # Handle mapping errors
        request, _ = self.start_authorization(userinfo)
        with patch.object(
            self.provider,
            "_remote_id_from_userinfo",
            new=Mock(side_effect=MappingException()),
        ):
            self.get_success(self.handler.handle_oidc_callback(request))
            self.assertRenderedError("mapping_error")

        # Handle ID token errors
        request, _ = self.start_authorization(userinfo)
        with self.fake_server.id_token_override({"iss": "https://bad.issuer/"}):
            self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_token")

        self.reset_mocks()

        # With userinfo fetching
        self.provider._user_profile_method = "userinfo_endpoint"
        # Without the "openid" scope, the FakeProvider does not generate an id_token
        request, _ = self.start_authorization(userinfo, scope="")
        self.get_success(self.handler.handle_oidc_callback(request))

        self.complete_sso_login.assert_called_once_with(
            expected_user_id,
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=False,
            auth_provider_session_id=None,
        )
        self.fake_server.post_token_handler.assert_called_once()
        self.fake_server.get_userinfo_handler.assert_called_once()
        self.render_error.assert_not_called()

        self.reset_mocks()

        # With an ID token, userinfo fetching and sid in the ID token
        self.provider._user_profile_method = "userinfo_endpoint"
        request, grant = self.start_authorization(userinfo, with_sid=True)
        self.assertIsNotNone(grant.sid)
        self.get_success(self.handler.handle_oidc_callback(request))

        self.complete_sso_login.assert_called_once_with(
            expected_user_id,
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=False,
            auth_provider_session_id=grant.sid,
        )
        self.fake_server.post_token_handler.assert_called_once()
        self.fake_server.get_userinfo_handler.assert_called_once()
        self.render_error.assert_not_called()

        # Handle userinfo fetching error
        request, _ = self.start_authorization(userinfo)
        with self.fake_server.buggy_endpoint(userinfo=True):
            self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("fetch_error")

        request, _ = self.start_authorization(userinfo)
        with self.fake_server.buggy_endpoint(token=True):
            self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("server_error")

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_callback_session(self) -> None:
        """The callback verifies the session presence and validity"""
        request = Mock(spec=["args", "getCookie", "cookies"])

        # Missing cookie
        request.args = {}
        request.getCookie.return_value = None
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("missing_session", "No session cookie found")

        # Missing session parameter
        request.args = {}
        request.getCookie.return_value = "session"
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_request", "State parameter is missing")

        # Invalid cookie
        request.args = {}
        request.args[b"state"] = [b"state"]
        request.getCookie.return_value = "session"
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_session")

        # Mismatching session
        session = self._generate_oidc_session_token(
            state="state",
            nonce="nonce",
            client_redirect_url="http://client/redirect",
        )
        request.args = {}
        request.args[b"state"] = [b"mismatching state"]
        request.getCookie.return_value = session
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("mismatching_session")

        # Valid session
        request.args = {}
        request.args[b"state"] = [b"state"]
        request.getCookie.return_value = session
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_request")

    @override_config(
        {"oidc_config": {**DEFAULT_CONFIG, "client_auth_method": "client_secret_post"}}
    )
    def test_exchange_code(self) -> None:
        """Code exchange behaves correctly and handles various error scenarios."""
        token = {
            "type": "Bearer",
            "access_token": "aabbcc",
        }

        self.fake_server.post_token_handler.side_effect = None
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            payload=token
        )
        code = "code"
        ret = self.get_success(self.provider._exchange_code(code))
        kwargs = self.fake_server.request.call_args[1]

        self.assertEqual(ret, token)
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["uri"], self.fake_server.token_endpoint)

        args = parse_qs(kwargs["data"].decode("utf-8"))
        self.assertEqual(args["grant_type"], ["authorization_code"])
        self.assertEqual(args["code"], [code])
        self.assertEqual(args["client_id"], [CLIENT_ID])
        self.assertEqual(args["client_secret"], [CLIENT_SECRET])
        self.assertEqual(args["redirect_uri"], [CALLBACK_URL])

        # Test error handling
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            code=400, payload={"error": "foo", "error_description": "bar"}
        )
        from synapse.handlers.oidc import OidcError

        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "foo")
        self.assertEqual(exc.value.error_description, "bar")

        # Internal server error with no JSON body
        self.fake_server.post_token_handler.return_value = FakeResponse(
            code=500, body=b"Not JSON"
        )
        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "server_error")

        # Internal server error with JSON body
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            code=500, payload={"error": "internal_server_error"}
        )

        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "internal_server_error")

        # 4xx error without "error" field
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            code=400, payload={}
        )
        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "server_error")

        # 2xx error with "error" field
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            code=200, payload={"error": "some_error"}
        )
        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "some_error")

    @override_config(
        {
            "oidc_config": {
                "enabled": True,
                "client_id": CLIENT_ID,
                "issuer": ISSUER,
                "client_auth_method": "client_secret_post",
                "client_secret_jwt_key": {
                    "key_file": _key_file_path(),
                    "jwt_header": {"alg": "ES256", "kid": "ABC789"},
                    "jwt_payload": {"iss": "DEFGHI"},
                },
            }
        }
    )
    def test_exchange_code_jwt_key(self) -> None:
        """Test that code exchange works with a JWK client secret."""
        from authlib.jose import jwt

        token = {
            "type": "Bearer",
            "access_token": "aabbcc",
        }

        self.fake_server.post_token_handler.side_effect = None
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            payload=token
        )
        code = "code"

        # advance the clock a bit before we start, so we aren't working with zero
        # timestamps.
        self.reactor.advance(1000)
        start_time = self.reactor.seconds()
        ret = self.get_success(self.provider._exchange_code(code))

        self.assertEqual(ret, token)

        # the request should have hit the token endpoint
        kwargs = self.fake_server.request.call_args[1]
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["uri"], self.fake_server.token_endpoint)

        # the client secret provided to the should be a jwt which can be checked with
        # the public key
        args = parse_qs(kwargs["data"].decode("utf-8"))
        secret = args["client_secret"][0]
        with open(_public_key_file_path()) as f:
            key = f.read()
        claims = jwt.decode(secret, key)
        self.assertEqual(claims.header["kid"], "ABC789")
        self.assertEqual(claims["aud"], ISSUER)
        self.assertEqual(claims["iss"], "DEFGHI")
        self.assertEqual(claims["sub"], CLIENT_ID)
        self.assertEqual(claims["iat"], start_time)
        self.assertGreater(claims["exp"], start_time)

        # check the rest of the POSTed data
        self.assertEqual(args["grant_type"], ["authorization_code"])
        self.assertEqual(args["code"], [code])
        self.assertEqual(args["client_id"], [CLIENT_ID])
        self.assertEqual(args["redirect_uri"], [CALLBACK_URL])

    @override_config(
        {
            "oidc_config": {
                "enabled": True,
                "client_id": CLIENT_ID,
                "issuer": ISSUER,
                "client_auth_method": "none",
            }
        }
    )
    def test_exchange_code_no_auth(self) -> None:
        """Test that code exchange works with no client secret."""
        token = {
            "type": "Bearer",
            "access_token": "aabbcc",
        }

        self.fake_server.post_token_handler.side_effect = None
        self.fake_server.post_token_handler.return_value = FakeResponse.json(
            payload=token
        )
        code = "code"
        ret = self.get_success(self.provider._exchange_code(code))

        self.assertEqual(ret, token)

        # the request should have hit the token endpoint
        kwargs = self.fake_server.request.call_args[1]
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["uri"], self.fake_server.token_endpoint)

        # check the POSTed data
        args = parse_qs(kwargs["data"].decode("utf-8"))
        self.assertEqual(args["grant_type"], ["authorization_code"])
        self.assertEqual(args["code"], [code])
        self.assertEqual(args["client_id"], [CLIENT_ID])
        self.assertEqual(args["redirect_uri"], [CALLBACK_URL])

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "user_mapping_provider": {
                    "module": __name__ + ".TestMappingProviderExtra"
                },
            }
        }
    )
    def test_extra_attributes(self) -> None:
        """
        Login while using a mapping provider that implements get_extra_attributes.
        """
        userinfo = {
            "sub": "foo",
            "username": "foo",
            "phone": "1234567",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))

        self.complete_sso_login.assert_called_once_with(
            "@foo:test",
            self.provider.idp_id,
            request,
            ANY,
            {"phone": "1234567"},
            new_user=True,
            auth_provider_session_id=None,
        )

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_map_userinfo_to_user(self) -> None:
        """Ensure that mapping the userinfo returned from a provider to an MXID works properly."""
        userinfo: dict = {
            "sub": "test_user",
            "username": "test_user",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_called_once_with(
            "@test_user:test",
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=True,
            auth_provider_session_id=None,
        )
        self.reset_mocks()

        # Some providers return an integer ID.
        userinfo = {
            "sub": 1234,
            "username": "test_user_2",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_called_once_with(
            "@test_user_2:test",
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=True,
            auth_provider_session_id=None,
        )
        self.reset_mocks()

        # Test if the mxid is already taken
        store = self.hs.get_datastores().main
        user3 = UserID.from_string("@test_user_3:test")
        self.get_success(
            store.register_user(user_id=user3.to_string(), password_hash=None)
        )
        userinfo = {"sub": "test3", "username": "test_user_3"}
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()
        self.assertRenderedError(
            "mapping_error",
            "Mapping provider does not support de-duplicating Matrix IDs",
        )

    @override_config({"oidc_config": {**DEFAULT_CONFIG, "allow_existing_users": True}})
    def test_map_userinfo_to_existing_user(self) -> None:
        """Existing users can log in with OpenID Connect when allow_existing_users is True."""
        store = self.hs.get_datastores().main
        user = UserID.from_string("@test_user:test")
        self.get_success(
            store.register_user(user_id=user.to_string(), password_hash=None)
        )

        # Map a user via SSO.
        userinfo = {
            "sub": "test",
            "username": "test_user",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_called_once_with(
            user.to_string(),
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=False,
            auth_provider_session_id=None,
        )
        self.reset_mocks()

        # Subsequent calls should map to the same mxid.
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_called_once_with(
            user.to_string(),
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=False,
            auth_provider_session_id=None,
        )
        self.reset_mocks()

        # Note that a second SSO user can be mapped to the same Matrix ID. (This
        # requires a unique sub, but something that maps to the same matrix ID,
        # in this case we'll just use the same username. A more realistic example
        # would be subs which are email addresses, and mapping from the localpart
        # of the email, e.g. bob@foo.com and bob@bar.com -> @bob:test.)
        userinfo = {
            "sub": "test1",
            "username": "test_user",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_called_once_with(
            user.to_string(),
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=False,
            auth_provider_session_id=None,
        )
        self.reset_mocks()

        # Register some non-exact matching cases.
        user2 = UserID.from_string("@TEST_user_2:test")
        self.get_success(
            store.register_user(user_id=user2.to_string(), password_hash=None)
        )
        user2_caps = UserID.from_string("@test_USER_2:test")
        self.get_success(
            store.register_user(user_id=user2_caps.to_string(), password_hash=None)
        )

        # Attempting to login without matching a name exactly is an error.
        userinfo = {
            "sub": "test2",
            "username": "TEST_USER_2",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()
        args = self.assertRenderedError("mapping_error")
        self.assertTrue(
            args[2].startswith(
                "Attempted to login as '@TEST_USER_2:test' but it matches more than one user inexactly:"
            )
        )

        # Logging in when matching a name exactly should work.
        user2 = UserID.from_string("@TEST_USER_2:test")
        self.get_success(
            store.register_user(user_id=user2.to_string(), password_hash=None)
        )

        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_called_once_with(
            "@TEST_USER_2:test",
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=False,
            auth_provider_session_id=None,
        )

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_map_userinfo_to_invalid_localpart(self) -> None:
        """If the mapping provider generates an invalid localpart it should be rejected."""
        userinfo = {"sub": "test2", "username": "föö"}
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("mapping_error", "localpart is invalid: föö")

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "user_mapping_provider": {
                    "module": __name__ + ".TestMappingProviderFailures"
                },
            }
        }
    )
    def test_map_userinfo_to_user_retries(self) -> None:
        """The mapping provider can retry generating an MXID if the MXID is already in use."""
        store = self.hs.get_datastores().main
        self.get_success(
            store.register_user(user_id="@test_user:test", password_hash=None)
        )
        userinfo = {
            "sub": "test",
            "username": "test_user",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))

        # test_user is already taken, so test_user1 gets registered instead.
        self.complete_sso_login.assert_called_once_with(
            "@test_user1:test",
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=True,
            auth_provider_session_id=None,
        )
        self.reset_mocks()

        # Register all of the potential mxids for a particular OIDC username.
        self.get_success(
            store.register_user(user_id="@tester:test", password_hash=None)
        )
        for i in range(1, 3):
            self.get_success(
                store.register_user(user_id="@tester%d:test" % i, password_hash=None)
            )

        # Now attempt to map to a username, this will fail since all potential usernames are taken.
        userinfo = {
            "sub": "tester",
            "username": "tester",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()
        self.assertRenderedError(
            "mapping_error", "Unable to generate a Matrix ID from the SSO response"
        )

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_empty_localpart(self) -> None:
        """Attempts to map onto an empty localpart should be rejected."""
        userinfo = {
            "sub": "tester",
            "username": "",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("mapping_error", "localpart is invalid: ")

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "user_mapping_provider": {
                    "config": {"localpart_template": "{{ user.username }}"}
                },
            }
        }
    )
    def test_null_localpart(self) -> None:
        """Mapping onto a null localpart via an empty OIDC attribute should be rejected"""
        userinfo = {
            "sub": "tester",
            "username": None,
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("mapping_error", "localpart is invalid: ")

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "attribute_requirements": [{"attribute": "test", "value": "foobar"}],
            }
        }
    )
    def test_attribute_requirements(self) -> None:
        """The required attributes must be met from the OIDC userinfo response."""
        # userinfo lacking "test": "foobar" attribute should fail.
        userinfo = {
            "sub": "tester",
            "username": "tester",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

        # userinfo with "test": "foobar" attribute should succeed.
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": "foobar",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))

        # check that the auth handler got called as expected
        self.complete_sso_login.assert_called_once_with(
            "@tester:test",
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=True,
            auth_provider_session_id=None,
        )

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "attribute_requirements": [{"attribute": "test", "value": "foobar"}],
            }
        }
    )
    def test_attribute_requirements_contains(self) -> None:
        """Test that auth succeeds if userinfo attribute CONTAINS required value"""
        # userinfo with "test": ["foobar", "foo", "bar"] attribute should succeed.
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": ["foobar", "foo", "bar"],
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))

        # check that the auth handler got called as expected
        self.complete_sso_login.assert_called_once_with(
            "@tester:test",
            self.provider.idp_id,
            request,
            ANY,
            None,
            new_user=True,
            auth_provider_session_id=None,
        )

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "attribute_requirements": [{"attribute": "test", "value": "foobar"}],
            }
        }
    )
    def test_attribute_requirements_mismatch(self) -> None:
        """
        Test that auth fails if attributes exist but don't match,
        or are non-string values.
        """
        # userinfo with "test": "not_foobar" attribute should fail
        userinfo: dict = {
            "sub": "tester",
            "username": "tester",
            "test": "not_foobar",
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

        # userinfo with "test": ["foo", "bar"] attribute should fail
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": ["foo", "bar"],
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

        # userinfo with "test": False attribute should fail
        # this is largely just to ensure we don't crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": False,
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

        # userinfo with "test": None attribute should fail
        # a value of None breaks the OIDC spec, but it's important to not crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": None,
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

        # userinfo with "test": 1 attribute should fail
        # this is largely just to ensure we don't crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": 1,
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

        # userinfo with "test": 3.14 attribute should fail
        # this is largely just to ensure we don't crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": 3.14,
        }
        request, _ = self.start_authorization(userinfo)
        self.get_success(self.handler.handle_oidc_callback(request))
        self.complete_sso_login.assert_not_called()

    def _generate_oidc_session_token(
        self,
        state: str,
        nonce: str,
        client_redirect_url: str,
        ui_auth_session_id: str = "",
    ) -> str:
        from synapse.handlers.oidc import OidcSessionData

        return self.handler._macaroon_generator.generate_oidc_session_token(
            state=state,
            session_data=OidcSessionData(
                idp_id=self.provider.idp_id,
                nonce=nonce,
                client_redirect_url=client_redirect_url,
                ui_auth_session_id=ui_auth_session_id,
            ),
        )


def _build_callback_request(
    code: str,
    state: str,
    session: str,
    ip_address: str = "10.0.0.1",
):
    """Builds a fake SynapseRequest to mock the browser callback

    Returns a Mock object which looks like the SynapseRequest we get from a browser
    after SSO (before we return to the client)

    Args:
        code: the authorization code which would have been returned by the OIDC
           provider
        state: the "state" param which would have been passed around in the
           query param. Should be the same as was embedded in the session in
           _build_oidc_session.
        session: the "session" which would have been passed around in the cookie.
        ip_address: the IP address to pretend the request came from
    """
    request = Mock(
        spec=[
            "args",
            "getCookie",
            "cookies",
            "requestHeaders",
            "getClientAddress",
            "getHeader",
        ]
    )

    request.cookies = []
    request.getCookie.return_value = session
    request.args = {}
    request.args[b"code"] = [code.encode("utf-8")]
    request.args[b"state"] = [state.encode("utf-8")]
    request.getClientAddress.return_value.host = ip_address
    return request
