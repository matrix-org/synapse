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
from urllib.parse import parse_qs, urlparse

from mock import Mock, patch

import attr
import pymacaroons

from twisted.python.failure import Failure
from twisted.web._newclient import ResponseDone

from synapse.handlers.oidc_handler import (
    MappingException,
    OidcError,
    OidcHandler,
    OidcMappingProvider,
)
from synapse.types import UserID

from tests.unittest import HomeserverTestCase, override_config


@attr.s
class FakeResponse:
    code = attr.ib()
    body = attr.ib()
    phrase = attr.ib()

    def deliverBody(self, protocol):
        protocol.dataReceived(self.body)
        protocol.connectionLost(Failure(ResponseDone()))


# These are a few constants that are used as config parameters in the tests.
ISSUER = "https://issuer/"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
BASE_URL = "https://synapse/"
CALLBACK_URL = BASE_URL + "_synapse/oidc/callback"
SCOPES = ["openid"]

AUTHORIZATION_ENDPOINT = ISSUER + "authorize"
TOKEN_ENDPOINT = ISSUER + "token"
USERINFO_ENDPOINT = ISSUER + "userinfo"
WELL_KNOWN = ISSUER + ".well-known/openid-configuration"
JWKS_URI = ISSUER + ".well-known/jwks.json"

# config for common cases
COMMON_CONFIG = {
    "discover": False,
    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "jwks_uri": JWKS_URI,
}


# The cookie name and path don't really matter, just that it has to be coherent
# between the callback & redirect handlers.
COOKIE_NAME = b"oidc_session"
COOKIE_PATH = "/_synapse/oidc"


class TestMappingProvider(OidcMappingProvider):
    @staticmethod
    def parse_config(config):
        return

    def get_remote_user_id(self, userinfo):
        return userinfo["sub"]

    async def map_user_attributes(self, userinfo, token):
        return {"localpart": userinfo["username"], "display_name": None}

    # Do not include get_extra_attributes to test backwards compatibility paths.


class TestMappingProviderExtra(TestMappingProvider):
    async def get_extra_attributes(self, userinfo, token):
        return {"phone": userinfo["phone"]}


def simple_async_mock(return_value=None, raises=None):
    # AsyncMock is not available in python3.5, this mimics part of its behaviour
    async def cb(*args, **kwargs):
        if raises:
            raise raises
        return return_value

    return Mock(side_effect=cb)


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


class OidcHandlerTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        self.http_client = Mock(spec=["get_json"])
        self.http_client.get_json.side_effect = get_json
        self.http_client.user_agent = "Synapse Test"

        config = self.default_config()
        config["public_baseurl"] = BASE_URL
        oidc_config = {}
        oidc_config["enabled"] = True
        oidc_config["client_id"] = CLIENT_ID
        oidc_config["client_secret"] = CLIENT_SECRET
        oidc_config["issuer"] = ISSUER
        oidc_config["scopes"] = SCOPES
        oidc_config["user_mapping_provider"] = {
            "module": __name__ + ".TestMappingProvider",
        }

        # Update this config with what's in the default config so that
        # override_config works as expected.
        oidc_config.update(config.get("oidc_config", {}))
        config["oidc_config"] = oidc_config

        hs = self.setup_test_homeserver(
            http_client=self.http_client,
            proxied_http_client=self.http_client,
            config=config,
        )

        self.handler = OidcHandler(hs)

        return hs

    def metadata_edit(self, values):
        return patch.dict(self.handler._provider_metadata, values)

    def assertRenderedError(self, error, error_description=None):
        args = self.handler._render_error.call_args[0]
        self.assertEqual(args[1], error)
        if error_description is not None:
            self.assertEqual(args[2], error_description)
        # Reset the render_error mock
        self.handler._render_error.reset_mock()

    def test_config(self):
        """Basic config correctly sets up the callback URL and client auth correctly."""
        self.assertEqual(self.handler._callback_url, CALLBACK_URL)
        self.assertEqual(self.handler._client_auth.client_id, CLIENT_ID)
        self.assertEqual(self.handler._client_auth.client_secret, CLIENT_SECRET)

    @override_config({"oidc_config": {"discover": True}})
    def test_discovery(self):
        """The handler should discover the endpoints from OIDC discovery document."""
        # This would throw if some metadata were invalid
        metadata = self.get_success(self.handler.load_metadata())
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)

        self.assertEqual(metadata.issuer, ISSUER)
        self.assertEqual(metadata.authorization_endpoint, AUTHORIZATION_ENDPOINT)
        self.assertEqual(metadata.token_endpoint, TOKEN_ENDPOINT)
        self.assertEqual(metadata.jwks_uri, JWKS_URI)
        # FIXME: it seems like authlib does not have that defined in its metadata models
        # self.assertEqual(metadata.userinfo_endpoint, USERINFO_ENDPOINT)

        # subsequent calls should be cached
        self.http_client.reset_mock()
        self.get_success(self.handler.load_metadata())
        self.http_client.get_json.assert_not_called()

    @override_config({"oidc_config": COMMON_CONFIG})
    def test_no_discovery(self):
        """When discovery is disabled, it should not try to load from discovery document."""
        self.get_success(self.handler.load_metadata())
        self.http_client.get_json.assert_not_called()

    @override_config({"oidc_config": COMMON_CONFIG})
    def test_load_jwks(self):
        """JWKS loading is done once (then cached) if used."""
        jwks = self.get_success(self.handler.load_jwks())
        self.http_client.get_json.assert_called_once_with(JWKS_URI)
        self.assertEqual(jwks, {"keys": []})

        # subsequent calls should be cached…
        self.http_client.reset_mock()
        self.get_success(self.handler.load_jwks())
        self.http_client.get_json.assert_not_called()

        # …unless forced
        self.http_client.reset_mock()
        self.get_success(self.handler.load_jwks(force=True))
        self.http_client.get_json.assert_called_once_with(JWKS_URI)

        # Throw if the JWKS uri is missing
        with self.metadata_edit({"jwks_uri": None}):
            self.get_failure(self.handler.load_jwks(force=True), RuntimeError)

        # Return empty key set if JWKS are not used
        self.handler._scopes = []  # not asking the openid scope
        self.http_client.get_json.reset_mock()
        jwks = self.get_success(self.handler.load_jwks(force=True))
        self.http_client.get_json.assert_not_called()
        self.assertEqual(jwks, {"keys": []})

    @override_config({"oidc_config": COMMON_CONFIG})
    def test_validate_config(self):
        """Provider metadatas are extensively validated."""
        h = self.handler

        # Default test config does not throw
        h._validate_metadata()

        with self.metadata_edit({"issuer": None}):
            self.assertRaisesRegex(ValueError, "issuer", h._validate_metadata)

        with self.metadata_edit({"issuer": "http://insecure/"}):
            self.assertRaisesRegex(ValueError, "issuer", h._validate_metadata)

        with self.metadata_edit({"issuer": "https://invalid/?because=query"}):
            self.assertRaisesRegex(ValueError, "issuer", h._validate_metadata)

        with self.metadata_edit({"authorization_endpoint": None}):
            self.assertRaisesRegex(
                ValueError, "authorization_endpoint", h._validate_metadata
            )

        with self.metadata_edit({"authorization_endpoint": "http://insecure/auth"}):
            self.assertRaisesRegex(
                ValueError, "authorization_endpoint", h._validate_metadata
            )

        with self.metadata_edit({"token_endpoint": None}):
            self.assertRaisesRegex(ValueError, "token_endpoint", h._validate_metadata)

        with self.metadata_edit({"token_endpoint": "http://insecure/token"}):
            self.assertRaisesRegex(ValueError, "token_endpoint", h._validate_metadata)

        with self.metadata_edit({"jwks_uri": None}):
            self.assertRaisesRegex(ValueError, "jwks_uri", h._validate_metadata)

        with self.metadata_edit({"jwks_uri": "http://insecure/jwks.json"}):
            self.assertRaisesRegex(ValueError, "jwks_uri", h._validate_metadata)

        with self.metadata_edit({"response_types_supported": ["id_token"]}):
            self.assertRaisesRegex(
                ValueError, "response_types_supported", h._validate_metadata
            )

        with self.metadata_edit(
            {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        ):
            # should not throw, as client_secret_basic is the default auth method
            h._validate_metadata()

        with self.metadata_edit(
            {"token_endpoint_auth_methods_supported": ["client_secret_post"]}
        ):
            self.assertRaisesRegex(
                ValueError,
                "token_endpoint_auth_methods_supported",
                h._validate_metadata,
            )

        # Tests for configs that require the userinfo endpoint
        self.assertFalse(h._uses_userinfo)
        self.assertEqual(h._user_profile_method, "auto")
        h._user_profile_method = "userinfo_endpoint"
        self.assertTrue(h._uses_userinfo)

        # Revert the profile method and do not request the "openid" scope.
        h._user_profile_method = "auto"
        h._scopes = []
        self.assertTrue(h._uses_userinfo)
        self.assertRaisesRegex(ValueError, "userinfo_endpoint", h._validate_metadata)

        with self.metadata_edit(
            {"userinfo_endpoint": USERINFO_ENDPOINT, "jwks_uri": None}
        ):
            # Shouldn't raise with a valid userinfo, even without
            h._validate_metadata()

    @override_config({"oidc_config": {"skip_verification": True}})
    def test_skip_verification(self):
        """Provider metadata validation can be disabled by config."""
        with self.metadata_edit({"issuer": "http://insecure"}):
            # This should not throw
            self.handler._validate_metadata()

    def test_redirect_request(self):
        """The redirect request has the right arguments & generates a valid session cookie."""
        req = Mock(spec=["addCookie"])
        url = self.get_success(
            self.handler.handle_redirect_request(req, b"http://client/redirect")
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

        # Check what is in the cookie
        # note: python3.5 mock does not have the .called_once() method
        calls = req.addCookie.call_args_list
        self.assertEqual(len(calls), 1)  # called once
        # For some reason, call.args does not work with python3.5
        args = calls[0][0]
        kwargs = calls[0][1]
        self.assertEqual(args[0], COOKIE_NAME)
        self.assertEqual(kwargs["path"], COOKIE_PATH)
        cookie = args[1]

        macaroon = pymacaroons.Macaroon.deserialize(cookie)
        state = self.handler._get_value_from_macaroon(macaroon, "state")
        nonce = self.handler._get_value_from_macaroon(macaroon, "nonce")
        redirect = self.handler._get_value_from_macaroon(
            macaroon, "client_redirect_url"
        )

        self.assertEqual(params["state"], [state])
        self.assertEqual(params["nonce"], [nonce])
        self.assertEqual(redirect, "http://client/redirect")

    def test_callback_error(self):
        """Errors from the provider returned in the callback are displayed."""
        self.handler._render_error = Mock()
        request = Mock(args={})
        request.args[b"error"] = [b"invalid_client"]
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_client", "")

        request.args[b"error_description"] = [b"some description"]
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_client", "some description")

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
        token = {
            "type": "bearer",
            "id_token": "id_token",
            "access_token": "access_token",
        }
        userinfo = {
            "sub": "foo",
            "preferred_username": "bar",
        }
        user_id = "@foo:domain.org"
        self.handler._render_error = Mock(return_value=None)
        self.handler._exchange_code = simple_async_mock(return_value=token)
        self.handler._parse_id_token = simple_async_mock(return_value=userinfo)
        self.handler._fetch_userinfo = simple_async_mock(return_value=userinfo)
        self.handler._map_userinfo_to_user = simple_async_mock(return_value=user_id)
        self.handler._auth_handler.complete_sso_login = simple_async_mock()
        request = Mock(
            spec=[
                "args",
                "getCookie",
                "addCookie",
                "requestHeaders",
                "getClientIP",
                "get_user_agent",
            ]
        )

        code = "code"
        state = "state"
        nonce = "nonce"
        client_redirect_url = "http://client/redirect"
        user_agent = "Browser"
        ip_address = "10.0.0.1"
        request.getCookie.return_value = self.handler._generate_oidc_session_token(
            state=state,
            nonce=nonce,
            client_redirect_url=client_redirect_url,
            ui_auth_session_id=None,
        )

        request.args = {}
        request.args[b"code"] = [code.encode("utf-8")]
        request.args[b"state"] = [state.encode("utf-8")]

        request.getClientIP.return_value = ip_address
        request.get_user_agent.return_value = user_agent

        self.get_success(self.handler.handle_oidc_callback(request))

        self.handler._auth_handler.complete_sso_login.assert_called_once_with(
            user_id, request, client_redirect_url, {},
        )
        self.handler._exchange_code.assert_called_once_with(code)
        self.handler._parse_id_token.assert_called_once_with(token, nonce=nonce)
        self.handler._map_userinfo_to_user.assert_called_once_with(
            userinfo, token, user_agent, ip_address
        )
        self.handler._fetch_userinfo.assert_not_called()
        self.handler._render_error.assert_not_called()

        # Handle mapping errors
        self.handler._map_userinfo_to_user = simple_async_mock(
            raises=MappingException()
        )
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("mapping_error")
        self.handler._map_userinfo_to_user = simple_async_mock(return_value=user_id)

        # Handle ID token errors
        self.handler._parse_id_token = simple_async_mock(raises=Exception())
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_token")

        self.handler._auth_handler.complete_sso_login.reset_mock()
        self.handler._exchange_code.reset_mock()
        self.handler._parse_id_token.reset_mock()
        self.handler._map_userinfo_to_user.reset_mock()
        self.handler._fetch_userinfo.reset_mock()

        # With userinfo fetching
        self.handler._scopes = []  # do not ask the "openid" scope
        self.get_success(self.handler.handle_oidc_callback(request))

        self.handler._auth_handler.complete_sso_login.assert_called_once_with(
            user_id, request, client_redirect_url, {},
        )
        self.handler._exchange_code.assert_called_once_with(code)
        self.handler._parse_id_token.assert_not_called()
        self.handler._map_userinfo_to_user.assert_called_once_with(
            userinfo, token, user_agent, ip_address
        )
        self.handler._fetch_userinfo.assert_called_once_with(token)
        self.handler._render_error.assert_not_called()

        # Handle userinfo fetching error
        self.handler._fetch_userinfo = simple_async_mock(raises=Exception())
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("fetch_error")

        # Handle code exchange failure
        self.handler._exchange_code = simple_async_mock(
            raises=OidcError("invalid_request")
        )
        self.get_success(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_request")

    def test_callback_session(self):
        """The callback verifies the session presence and validity"""
        self.handler._render_error = Mock(return_value=None)
        request = Mock(spec=["args", "getCookie", "addCookie"])

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
        session = self.handler._generate_oidc_session_token(
            state="state",
            nonce="nonce",
            client_redirect_url="http://client/redirect",
            ui_auth_session_id=None,
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

    @override_config({"oidc_config": {"client_auth_method": "client_secret_post"}})
    def test_exchange_code(self):
        """Code exchange behaves correctly and handles various error scenarios."""
        token = {"type": "bearer"}
        token_json = json.dumps(token).encode("utf-8")
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(code=200, phrase=b"OK", body=token_json)
        )
        code = "code"
        ret = self.get_success(self.handler._exchange_code(code))
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
        exc = self.get_failure(self.handler._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "foo")
        self.assertEqual(exc.value.error_description, "bar")

        # Internal server error with no JSON body
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=500, phrase=b"Internal Server Error", body=b"Not JSON",
            )
        )
        exc = self.get_failure(self.handler._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "server_error")

        # Internal server error with JSON body
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=500,
                phrase=b"Internal Server Error",
                body=b'{"error": "internal_server_error"}',
            )
        )

        exc = self.get_failure(self.handler._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "internal_server_error")

        # 4xx error without "error" field
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(code=400, phrase=b"Bad request", body=b"{}",)
        )
        exc = self.get_failure(self.handler._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "server_error")

        # 2xx error with "error" field
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(
                code=200, phrase=b"OK", body=b'{"error": "some_error"}',
            )
        )
        exc = self.get_failure(self.handler._exchange_code(code), OidcError)
        self.assertEqual(exc.value.error, "some_error")

    @override_config(
        {
            "oidc_config": {
                "user_mapping_provider": {
                    "module": __name__ + ".TestMappingProviderExtra"
                }
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
            "phone": "1234567",
        }
        user_id = "@foo:domain.org"
        self.handler._exchange_code = simple_async_mock(return_value=token)
        self.handler._parse_id_token = simple_async_mock(return_value=userinfo)
        self.handler._map_userinfo_to_user = simple_async_mock(return_value=user_id)
        self.handler._auth_handler.complete_sso_login = simple_async_mock()
        request = Mock(
            spec=[
                "args",
                "getCookie",
                "addCookie",
                "requestHeaders",
                "getClientIP",
                "get_user_agent",
            ]
        )

        state = "state"
        client_redirect_url = "http://client/redirect"
        request.getCookie.return_value = self.handler._generate_oidc_session_token(
            state=state,
            nonce="nonce",
            client_redirect_url=client_redirect_url,
            ui_auth_session_id=None,
        )

        request.args = {}
        request.args[b"code"] = [b"code"]
        request.args[b"state"] = [state.encode("utf-8")]

        request.getClientIP.return_value = "10.0.0.1"
        request.get_user_agent.return_value = "Browser"

        self.get_success(self.handler.handle_oidc_callback(request))

        self.handler._auth_handler.complete_sso_login.assert_called_once_with(
            user_id, request, client_redirect_url, {"phone": "1234567"},
        )

    def test_map_userinfo_to_user(self):
        """Ensure that mapping the userinfo returned from a provider to an MXID works properly."""
        userinfo = {
            "sub": "test_user",
            "username": "test_user",
        }
        # The token doesn't matter with the default user mapping provider.
        token = {}
        mxid = self.get_success(
            self.handler._map_userinfo_to_user(
                userinfo, token, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@test_user:test")

        # Some providers return an integer ID.
        userinfo = {
            "sub": 1234,
            "username": "test_user_2",
        }
        mxid = self.get_success(
            self.handler._map_userinfo_to_user(
                userinfo, token, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@test_user_2:test")

        # Test if the mxid is already taken
        store = self.hs.get_datastore()
        user3 = UserID.from_string("@test_user_3:test")
        self.get_success(
            store.register_user(user_id=user3.to_string(), password_hash=None)
        )
        userinfo = {"sub": "test3", "username": "test_user_3"}
        e = self.get_failure(
            self.handler._map_userinfo_to_user(
                userinfo, token, "user-agent", "10.10.10.10"
            ),
            MappingException,
        )
        self.assertEqual(str(e.value), "mxid '@test_user_3:test' is already taken")

    @override_config({"oidc_config": {"allow_existing_users": True}})
    def test_map_userinfo_to_existing_user(self):
        """Existing users can log in with OpenID Connect when allow_existing_users is True."""
        store = self.hs.get_datastore()
        user4 = UserID.from_string("@test_user_4:test")
        self.get_success(
            store.register_user(user_id=user4.to_string(), password_hash=None)
        )
        userinfo = {
            "sub": "test4",
            "username": "test_user_4",
        }
        token = {}
        mxid = self.get_success(
            self.handler._map_userinfo_to_user(
                userinfo, token, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@test_user_4:test")
