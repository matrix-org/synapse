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
import os
from unittest.mock import ANY, Mock, patch
from urllib.parse import parse_qs, urlparse

import pymacaroons

from synapse.handlers.sso import MappingException
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util.macaroons import get_value_from_macaroon

from tests.test_utils import FakeResponse, get_awaitable_result, simple_async_mock
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

AUTHORIZATION_ENDPOINT = ISSUER + "authorize"
TOKEN_ENDPOINT = ISSUER + "token"
USERINFO_ENDPOINT = ISSUER + "userinfo"
WELL_KNOWN = ISSUER + ".well-known/openid-configuration"
JWKS_URI = ISSUER + ".well-known/jwks.json"

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
    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "jwks_uri": JWKS_URI,
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


async def get_json(url):
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
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
    elif url == JWKS_URI:
        return {"keys": []}


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

    def default_config(self):
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        return config

    def make_homeserver(self, reactor, clock):
        self.http_client = Mock(spec=["get_json"])
        self.http_client.get_json.side_effect = get_json
        self.http_client.user_agent = "Synapse Test"

        hs = self.setup_test_homeserver(proxied_http_client=self.http_client)

        self.handler = hs.get_oidc_handler()
        self.provider = self.handler._providers["oidc"]
        sso_handler = hs.get_sso_handler()
        # Mock the render error method.
        self.render_error = Mock(return_value=None)
        sso_handler.render_error = self.render_error

        # Reduce the number of attempts when generating MXIDs.
        sso_handler._MAP_USERNAME_RETRIES = 3

        return hs

    def metadata_edit(self, values):
        """Modify the result that will be returned by the well-known query"""

        async def patched_get_json(uri):
            res = await get_json(uri)
            if uri == WELL_KNOWN:
                res.update(values)
            return res

        return patch.object(self.http_client, "get_json", patched_get_json)

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
    def test_config(self):
        """Basic config correctly sets up the callback URL and client auth correctly."""
        self.assertEqual(self.provider._callback_url, CALLBACK_URL)
        self.assertEqual(self.provider._client_auth.client_id, CLIENT_ID)
        self.assertEqual(self.provider._client_auth.client_secret, CLIENT_SECRET)

    @override_config({"oidc_config": {**DEFAULT_CONFIG, "discover": True}})
    def test_discovery(self):
        """The handler should discover the endpoints from OIDC discovery document."""
        # This would throw if some metadata were invalid
        metadata = self.get_success(self.provider.load_metadata())
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)

        self.assertEqual(metadata.issuer, ISSUER)
        self.assertEqual(metadata.authorization_endpoint, AUTHORIZATION_ENDPOINT)
        self.assertEqual(metadata.token_endpoint, TOKEN_ENDPOINT)
        self.assertEqual(metadata.jwks_uri, JWKS_URI)
        # FIXME: it seems like authlib does not have that defined in its metadata models
        # self.assertEqual(metadata.userinfo_endpoint, USERINFO_ENDPOINT)

        # subsequent calls should be cached
        self.http_client.reset_mock()
        self.get_success(self.provider.load_metadata())
        self.http_client.get_json.assert_not_called()

    @override_config({"oidc_config": EXPLICIT_ENDPOINT_CONFIG})
    def test_no_discovery(self):
        """When discovery is disabled, it should not try to load from discovery document."""
        self.get_success(self.provider.load_metadata())
        self.http_client.get_json.assert_not_called()

    @override_config({"oidc_config": EXPLICIT_ENDPOINT_CONFIG})
    def test_load_jwks(self):
        """JWKS loading is done once (then cached) if used."""
        jwks = self.get_success(self.provider.load_jwks())
        self.http_client.get_json.assert_called_once_with(JWKS_URI)
        self.assertEqual(jwks, {"keys": []})

        # subsequent calls should be cached…
        self.http_client.reset_mock()
        self.get_success(self.provider.load_jwks())
        self.http_client.get_json.assert_not_called()

        # …unless forced
        self.http_client.reset_mock()
        self.get_success(self.provider.load_jwks(force=True))
        self.http_client.get_json.assert_called_once_with(JWKS_URI)

        # Throw if the JWKS uri is missing
        original = self.provider.load_metadata

        async def patched_load_metadata():
            m = (await original()).copy()
            m.update({"jwks_uri": None})
            return m

        with patch.object(self.provider, "load_metadata", patched_load_metadata):
            self.get_failure(self.provider.load_jwks(force=True), RuntimeError)

        # Return empty key set if JWKS are not used
        self.provider._scopes = []  # not asking the openid scope
        self.http_client.get_json.reset_mock()
        jwks = self.get_success(self.provider.load_jwks(force=True))
        self.http_client.get_json.assert_not_called()
        self.assertEqual(jwks, {"keys": []})

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_validate_config(self):
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
    def test_skip_verification(self):
        """Provider metadata validation can be disabled by config."""
        with self.metadata_edit({"issuer": "http://insecure"}):
            # This should not throw
            get_awaitable_result(self.provider.load_metadata())

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_redirect_request(self):
        """The redirect request has the right arguments & generates a valid session cookie."""
        req = Mock(spec=["cookies"])
        req.cookies = []

        url = self.get_success(
            self.provider.handle_redirect_request(req, b"http://client/redirect")
        )
        url = urlparse(url)
        auth_endpoint = urlparse(AUTHORIZATION_ENDPOINT)

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
    def test_callback_error(self):
        """Errors from the provider returned in the callback are displayed."""
        request = Mock(args={})
        request.args[b"error"] = [b"invalid_client"]
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_client", "")

        request.args[b"error_description"] = [b"some description"]
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_client", "some description")

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_callback(self):
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

        token = {
            "type": "bearer",
            "id_token": "id_token",
            "access_token": "access_token",
        }
        username = "bar"
        userinfo = {
            "sub": "foo",
            "username": username,
        }
        expected_user_id = "@%s:%s" % (username, self.hs.hostname)
        self.provider._exchange_code = simple_async_mock(return_value=token)
        self.provider._parse_id_token = simple_async_mock(return_value=userinfo)
        self.provider._fetch_userinfo = simple_async_mock(return_value=userinfo)
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        code = "code"
        state = "state"
        nonce = "nonce"
        client_redirect_url = "http://client/redirect"
        user_agent = "Browser"
        ip_address = "10.0.0.1"
        session = self._generate_oidc_session_token(state, nonce, client_redirect_url)
        request = _build_callback_request(
            code, state, session, user_agent=user_agent, ip_address=ip_address
        )

        self.get_success(self.handler.handle_oidc_callback(request))

        auth_handler.complete_sso_login.assert_called_once_with(
            expected_user_id, "oidc", request, client_redirect_url, None, new_user=True
        )
        self.provider._exchange_code.assert_called_once_with(code)
        self.provider._parse_id_token.assert_called_once_with(token, nonce=nonce)
        self.provider._fetch_userinfo.assert_not_called()
        self.render_error.assert_not_called()

        # Handle mapping errors
        with patch.object(
            self.provider,
            "_remote_id_from_userinfo",
            new=Mock(side_effect=MappingException()),
        ):
            self.get_success(self.handler.handle_oidc_callback(request))
            self.assertRenderedError("mapping_error")

        # Handle ID token errors
        self.provider._parse_id_token = simple_async_mock(raises=Exception())
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_token")

        auth_handler.complete_sso_login.reset_mock()
        self.provider._exchange_code.reset_mock()
        self.provider._parse_id_token.reset_mock()
        self.provider._fetch_userinfo.reset_mock()

        # With userinfo fetching
        self.provider._scopes = []  # do not ask the "openid" scope
        self.get_success(self.handler.handle_oidc_callback(request))

        auth_handler.complete_sso_login.assert_called_once_with(
            expected_user_id, "oidc", request, client_redirect_url, None, new_user=False
        )
        self.provider._exchange_code.assert_called_once_with(code)
        self.provider._parse_id_token.assert_not_called()
        self.provider._fetch_userinfo.assert_called_once_with(token)
        self.render_error.assert_not_called()

        # Handle userinfo fetching error
        self.provider._fetch_userinfo = simple_async_mock(raises=Exception())
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("fetch_error")

        # Handle code exchange failure
        from synapse.handlers.oidc_handler import OidcError

        self.provider._exchange_code = simple_async_mock(
            raises=OidcError("invalid_request")
        )
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_request")

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_callback_session(self):
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
    def test_exchange_code(self):
        """Code exchange behaves correctly and handles various error scenarios."""
        token = {"type": "bearer"}
        token_json = json.dumps(token).encode("utf-8")
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(code=200, phrase=b"OK", body=token_json)
        )
        code = "code"
        ret = self.get_success(self.provider._exchange_code(code))
        kwargs = self.http_client.request.call_args[1]

        self.assertEqual(ret, token)
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["uri"], TOKEN_ENDPOINT)

        args = parse_qs(kwargs["data"].decode("utf-8"))
        self.assertEqual(args["grant_type"], ["authorization_code"])
        self.assertEqual(args["code"], [code])
        self.assertEqual(args["client_id"], [CLIENT_ID])
        self.assertEqual(args["client_secret"], [CLIENT_SECRET])
        self.assertEqual(args["redirect_uri"], [CALLBACK_URL])

        # Test error handling
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=400,
                phrase=b"Bad Request",
                body=b'{"error": "foo", "error_description": "bar"}',
            )
        )
        from synapse.handlers.oidc_handler import OidcError

        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "foo")
        self.assertEqual(exc.value.error_description, "bar")

        # Internal server error with no JSON body
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=500,
                phrase=b"Internal Server Error",
                body=b"Not JSON",
            )
        )
        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "server_error")

        # Internal server error with JSON body
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=500,
                phrase=b"Internal Server Error",
                body=b'{"error": "internal_server_error"}',
            )
        )

        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "internal_server_error")

        # 4xx error without "error" field
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=400,
                phrase=b"Bad request",
                body=b"{}",
            )
        )
        exc = self.get_failure(self.provider._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "server_error")

        # 2xx error with "error" field
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=200,
                phrase=b"OK",
                body=b'{"error": "some_error"}',
            )
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
    def test_exchange_code_jwt_key(self):
        """Test that code exchange works with a JWK client secret."""
        from authlib.jose import jwt

        token = {"type": "bearer"}
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=200, phrase=b"OK", body=json.dumps(token).encode("utf-8")
            )
        )
        code = "code"

        # advance the clock a bit before we start, so we aren't working with zero
        # timestamps.
        self.reactor.advance(1000)
        start_time = self.reactor.seconds()
        ret = self.get_success(self.provider._exchange_code(code))

        self.assertEqual(ret, token)

        # the request should have hit the token endpoint
        kwargs = self.http_client.request.call_args[1]
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["uri"], TOKEN_ENDPOINT)

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
    def test_exchange_code_no_auth(self):
        """Test that code exchange works with no client secret."""
        token = {"type": "bearer"}
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=200, phrase=b"OK", body=json.dumps(token).encode("utf-8")
            )
        )
        code = "code"
        ret = self.get_success(self.provider._exchange_code(code))

        self.assertEqual(ret, token)

        # the request should have hit the token endpoint
        kwargs = self.http_client.request.call_args[1]
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["uri"], TOKEN_ENDPOINT)

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
    def test_extra_attributes(self):
        """
        Login while using a mapping provider that implements get_extra_attributes.
        """
        token = {
            "type": "bearer",
            "id_token": "id_token",
            "access_token": "access_token",
        }
        userinfo = {
            "sub": "foo",
            "username": "foo",
            "phone": "1234567",
        }
        self.provider._exchange_code = simple_async_mock(return_value=token)
        self.provider._parse_id_token = simple_async_mock(return_value=userinfo)
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        state = "state"
        client_redirect_url = "http://client/redirect"
        session = self._generate_oidc_session_token(
            state=state,
            nonce="nonce",
            client_redirect_url=client_redirect_url,
        )
        request = _build_callback_request("code", state, session)

        self.get_success(self.handler.handle_oidc_callback(request))

        auth_handler.complete_sso_login.assert_called_once_with(
            "@foo:test",
            "oidc",
            request,
            client_redirect_url,
            {"phone": "1234567"},
            new_user=True,
        )

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_map_userinfo_to_user(self):
        """Ensure that mapping the userinfo returned from a provider to an MXID works properly."""
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        userinfo = {
            "sub": "test_user",
            "username": "test_user",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user:test", "oidc", ANY, ANY, None, new_user=True
        )
        auth_handler.complete_sso_login.reset_mock()

        # Some providers return an integer ID.
        userinfo = {
            "sub": 1234,
            "username": "test_user_2",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user_2:test", "oidc", ANY, ANY, None, new_user=True
        )
        auth_handler.complete_sso_login.reset_mock()

        # Test if the mxid is already taken
        store = self.hs.get_datastore()
        user3 = UserID.from_string("@test_user_3:test")
        self.get_success(
            store.register_user(user_id=user3.to_string(), password_hash=None)
        )
        userinfo = {"sub": "test3", "username": "test_user_3"}
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()
        self.assertRenderedError(
            "mapping_error",
            "Mapping provider does not support de-duplicating Matrix IDs",
        )

    @override_config({"oidc_config": {**DEFAULT_CONFIG, "allow_existing_users": True}})
    def test_map_userinfo_to_existing_user(self):
        """Existing users can log in with OpenID Connect when allow_existing_users is True."""
        store = self.hs.get_datastore()
        user = UserID.from_string("@test_user:test")
        self.get_success(
            store.register_user(user_id=user.to_string(), password_hash=None)
        )

        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        # Map a user via SSO.
        userinfo = {
            "sub": "test",
            "username": "test_user",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_called_once_with(
            user.to_string(), "oidc", ANY, ANY, None, new_user=False
        )
        auth_handler.complete_sso_login.reset_mock()

        # Subsequent calls should map to the same mxid.
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_called_once_with(
            user.to_string(), "oidc", ANY, ANY, None, new_user=False
        )
        auth_handler.complete_sso_login.reset_mock()

        # Note that a second SSO user can be mapped to the same Matrix ID. (This
        # requires a unique sub, but something that maps to the same matrix ID,
        # in this case we'll just use the same username. A more realistic example
        # would be subs which are email addresses, and mapping from the localpart
        # of the email, e.g. bob@foo.com and bob@bar.com -> @bob:test.)
        userinfo = {
            "sub": "test1",
            "username": "test_user",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_called_once_with(
            user.to_string(), "oidc", ANY, ANY, None, new_user=False
        )
        auth_handler.complete_sso_login.reset_mock()

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
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()
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

        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_called_once_with(
            "@TEST_USER_2:test", "oidc", ANY, ANY, None, new_user=False
        )

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_map_userinfo_to_invalid_localpart(self):
        """If the mapping provider generates an invalid localpart it should be rejected."""
        self.get_success(
            _make_callback_with_userinfo(self.hs, {"sub": "test2", "username": "föö"})
        )
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
    def test_map_userinfo_to_user_retries(self):
        """The mapping provider can retry generating an MXID if the MXID is already in use."""
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        store = self.hs.get_datastore()
        self.get_success(
            store.register_user(user_id="@test_user:test", password_hash=None)
        )
        userinfo = {
            "sub": "test",
            "username": "test_user",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))

        # test_user is already taken, so test_user1 gets registered instead.
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user1:test", "oidc", ANY, ANY, None, new_user=True
        )
        auth_handler.complete_sso_login.reset_mock()

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
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()
        self.assertRenderedError(
            "mapping_error", "Unable to generate a Matrix ID from the SSO response"
        )

    @override_config({"oidc_config": DEFAULT_CONFIG})
    def test_empty_localpart(self):
        """Attempts to map onto an empty localpart should be rejected."""
        userinfo = {
            "sub": "tester",
            "username": "",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
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
    def test_null_localpart(self):
        """Mapping onto a null localpart via an empty OIDC attribute should be rejected"""
        userinfo = {
            "sub": "tester",
            "username": None,
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        self.assertRenderedError("mapping_error", "localpart is invalid: ")

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "attribute_requirements": [{"attribute": "test", "value": "foobar"}],
            }
        }
    )
    def test_attribute_requirements(self):
        """The required attributes must be met from the OIDC userinfo response."""
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        # userinfo lacking "test": "foobar" attribute should fail.
        userinfo = {
            "sub": "tester",
            "username": "tester",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

        # userinfo with "test": "foobar" attribute should succeed.
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": "foobar",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))

        # check that the auth handler got called as expected
        auth_handler.complete_sso_login.assert_called_once_with(
            "@tester:test", "oidc", ANY, ANY, None, new_user=True
        )

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "attribute_requirements": [{"attribute": "test", "value": "foobar"}],
            }
        }
    )
    def test_attribute_requirements_contains(self):
        """Test that auth succeeds if userinfo attribute CONTAINS required value"""
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()
        # userinfo with "test": ["foobar", "foo", "bar"] attribute should succeed.
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": ["foobar", "foo", "bar"],
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))

        # check that the auth handler got called as expected
        auth_handler.complete_sso_login.assert_called_once_with(
            "@tester:test", "oidc", ANY, ANY, None, new_user=True
        )

    @override_config(
        {
            "oidc_config": {
                **DEFAULT_CONFIG,
                "attribute_requirements": [{"attribute": "test", "value": "foobar"}],
            }
        }
    )
    def test_attribute_requirements_mismatch(self):
        """
        Test that auth fails if attributes exist but don't match,
        or are non-string values.
        """
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()
        # userinfo with "test": "not_foobar" attribute should fail
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": "not_foobar",
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

        # userinfo with "test": ["foo", "bar"] attribute should fail
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": ["foo", "bar"],
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

        # userinfo with "test": False attribute should fail
        # this is largely just to ensure we don't crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": False,
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

        # userinfo with "test": None attribute should fail
        # a value of None breaks the OIDC spec, but it's important to not crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": None,
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

        # userinfo with "test": 1 attribute should fail
        # this is largely just to ensure we don't crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": 1,
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

        # userinfo with "test": 3.14 attribute should fail
        # this is largely just to ensure we don't crash here
        userinfo = {
            "sub": "tester",
            "username": "tester",
            "test": 3.14,
        }
        self.get_success(_make_callback_with_userinfo(self.hs, userinfo))
        auth_handler.complete_sso_login.assert_not_called()

    def _generate_oidc_session_token(
        self,
        state: str,
        nonce: str,
        client_redirect_url: str,
        ui_auth_session_id: str = "",
    ) -> str:
        from synapse.handlers.oidc_handler import OidcSessionData

        return self.handler._token_generator.generate_oidc_session_token(
            state=state,
            session_data=OidcSessionData(
                idp_id="oidc",
                nonce=nonce,
                client_redirect_url=client_redirect_url,
                ui_auth_session_id=ui_auth_session_id,
            ),
        )


async def _make_callback_with_userinfo(
    hs: HomeServer, userinfo: dict, client_redirect_url: str = "http://client/redirect"
) -> None:
    """Mock up an OIDC callback with the given userinfo dict

    We'll pull out the OIDC handler from the homeserver, stub out a couple of methods,
    and poke in the userinfo dict as if it were the response to an OIDC userinfo call.

    Args:
        hs: the HomeServer impl to send the callback to.
        userinfo: the OIDC userinfo dict
        client_redirect_url: the URL to redirect to on success.
    """
    from synapse.handlers.oidc_handler import OidcSessionData

    handler = hs.get_oidc_handler()
    provider = handler._providers["oidc"]
    provider._exchange_code = simple_async_mock(return_value={})
    provider._parse_id_token = simple_async_mock(return_value=userinfo)
    provider._fetch_userinfo = simple_async_mock(return_value=userinfo)

    state = "state"
    session = handler._token_generator.generate_oidc_session_token(
        state=state,
        session_data=OidcSessionData(
            idp_id="oidc",
            nonce="nonce",
            client_redirect_url=client_redirect_url,
            ui_auth_session_id="",
        ),
    )
    request = _build_callback_request("code", state, session)

    await handler.handle_oidc_callback(request)


def _build_callback_request(
    code: str,
    state: str,
    session: str,
    user_agent: str = "Browser",
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
        user_agent: the user-agent to present
        ip_address: the IP address to pretend the request came from
    """
    request = Mock(
        spec=[
            "args",
            "getCookie",
            "cookies",
            "requestHeaders",
            "getClientIP",
            "getHeader",
        ]
    )

    request.cookies = []
    request.getCookie.return_value = session
    request.args = {}
    request.args[b"code"] = [code.encode("utf-8")]
    request.args[b"state"] = [state.encode("utf-8")]
    request.getClientIP.return_value = ip_address
    return request
