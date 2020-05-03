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
from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

from mock import Mock

import attr
import pymacaroons

from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.web._newclient import ResponseDone

from synapse.handlers.oidc_handler import OidcError, OidcHandler, OidcMappingProvider
from synapse.types import UserID

from tests.unittest import HomeserverTestCase, override_config


@attr.s
class FakeResponse(object):
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

MockedMappingProvider = Mock(OidcMappingProvider)


def simple_async_mock(return_value=None):
    # AsyncMock is not available in python3.5, this mimics part of its behaviour
    async def cb(*args, **kwargs):
        return return_value

    return Mock(side_effect=cb)


def get_jwks():
    return {"keys": []}


def get_metadata():
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


async def get_json(url):
    # Mock get_json calls to handle jwks & oidc discovery endpoints
    if url == WELL_KNOWN:
        return get_metadata()
    elif url == JWKS_URI:
        return get_jwks()


@contextmanager
def metadata_edit(handler, values):
    # Temporarily edits the provider metadata
    meta = handler._provider_metadata
    saved = {}

    for (key, value) in values.items():
        saved[key] = meta[key]
        meta[key] = value

    yield

    for (key, value) in values.items():
        meta[key] = saved[key]


class OidcHandlerTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        self.http_client = Mock(spec=["get_json"])
        self.http_client.get_json.side_effect = get_json
        self.http_client.user_agent = "Synapse Test"

        config = self.default_config()
        config["public_baseurl"] = BASE_URL
        oidc_config = config.get("oidc_config", {})
        oidc_config["enabled"] = True
        oidc_config["client_id"] = CLIENT_ID
        oidc_config["client_secret"] = CLIENT_SECRET
        oidc_config["issuer"] = ISSUER
        oidc_config["scopes"] = SCOPES
        oidc_config["user_mapping_provider"] = {
            "module": __name__ + ".MockedMappingProvider"
        }
        config["oidc_config"] = oidc_config

        hs = self.setup_test_homeserver(
            http_client=self.http_client,
            proxied_http_client=self.http_client,
            config=config,
        )

        self.handler = OidcHandler(hs)

        return hs

    def assertRenderedError(self, error, error_description=None):
        args = self.handler._render_error.call_args[0]
        self.assertEqual(args[1], error)
        if error_description is not None:
            self.assertEqual(args[2], error_description)

    def test_config(self):
        self.assertEqual(self.handler._callback_url, CALLBACK_URL)
        self.assertEqual(self.handler._client_auth.client_id, CLIENT_ID)
        self.assertEqual(self.handler._client_auth.client_secret, CLIENT_SECRET)

    @override_config({"oidc_config": {"discover": True}})
    @defer.inlineCallbacks
    def test_discovery(self):
        # This would throw if some metadata were invalid
        metadata = yield defer.ensureDeferred(self.handler.load_metadata())
        self.http_client.get_json.assert_called_once_with(WELL_KNOWN)

        self.assertEqual(metadata.issuer, ISSUER)
        self.assertEqual(metadata.authorization_endpoint, AUTHORIZATION_ENDPOINT)
        self.assertEqual(metadata.token_endpoint, TOKEN_ENDPOINT)
        self.assertEqual(metadata.jwks_uri, JWKS_URI)
        # FIXME: it seems like authlib does not have that defined in its metadata models
        # self.assertEqual(metadata.userinfo_endpoint, USERINFO_ENDPOINT)

        # subsequent calls should be cached
        self.http_client.reset_mock()
        yield defer.ensureDeferred(self.handler.load_metadata())
        self.http_client.get_json.assert_not_called()

    @override_config({"oidc_config": COMMON_CONFIG})
    @defer.inlineCallbacks
    def test_no_discovery(self):
        yield defer.ensureDeferred(self.handler.load_metadata())
        self.http_client.get_json.assert_not_called()

    @override_config({"oidc_config": COMMON_CONFIG})
    @defer.inlineCallbacks
    def test_load_jwks(self):
        jwks = yield defer.ensureDeferred(self.handler.load_jwks())
        self.http_client.get_json.assert_called_once_with(JWKS_URI)
        self.assertEqual(jwks, {"keys": []})

        # subsequent calls should be cached…
        self.http_client.reset_mock()
        yield defer.ensureDeferred(self.handler.load_jwks())
        self.http_client.get_json.assert_not_called()

        # …unless forced
        self.http_client.reset_mock()
        yield defer.ensureDeferred(self.handler.load_jwks(force=True))
        self.http_client.get_json.assert_called_once_with(JWKS_URI)

    @override_config({"oidc_config": COMMON_CONFIG})
    def test_validate_config(self):
        h = self.handler

        # Default test config does not throw
        h._validate_metadata()

        with metadata_edit(h, {"issuer": None}):
            self.assertRaisesRegex(ValueError, "issuer", h._validate_metadata)

        with metadata_edit(h, {"issuer": "http://insecure/"}):
            self.assertRaisesRegex(ValueError, "issuer", h._validate_metadata)

        with metadata_edit(h, {"issuer": "https://invalid/?because=query"}):
            self.assertRaisesRegex(ValueError, "issuer", h._validate_metadata)

        with metadata_edit(h, {"authorization_endpoint": None}):
            self.assertRaisesRegex(
                ValueError, "authorization_endpoint", h._validate_metadata
            )

        with metadata_edit(h, {"authorization_endpoint": "http://insecure/auth"}):
            self.assertRaisesRegex(
                ValueError, "authorization_endpoint", h._validate_metadata
            )

        with metadata_edit(h, {"token_endpoint": None}):
            self.assertRaisesRegex(ValueError, "token_endpoint", h._validate_metadata)

        with metadata_edit(h, {"token_endpoint": "http://insecure/token"}):
            self.assertRaisesRegex(ValueError, "token_endpoint", h._validate_metadata)

        with metadata_edit(h, {"jwks_uri": None}):
            self.assertRaisesRegex(ValueError, "jwks_uri", h._validate_metadata)

        with metadata_edit(h, {"jwks_uri": "http://insecure/jwks.json"}):
            self.assertRaisesRegex(ValueError, "jwks_uri", h._validate_metadata)

        # Tests for configs that the userinfo endpoint
        self.assertFalse(h._uses_userinfo)
        h._scopes = []  # do not request the openid scope
        self.assertTrue(h._uses_userinfo)
        self.assertRaisesRegex(ValueError, "userinfo_endpoint", h._validate_metadata)

        with metadata_edit(
            h, {"userinfo_endpoint": USERINFO_ENDPOINT, "jwks_uri": None}
        ):
            # Shouldn't raise with a valid userinfo, even without
            h._validate_metadata()

    @override_config({"oidc_config": {"skip_verification": True}})
    def test_skip_verification(self):
        with metadata_edit(self.handler, {"issuer": "http://insecure"}):
            # This should not throw
            self.handler._validate_metadata()

    @defer.inlineCallbacks
    def test_redirect_request(self):
        req = Mock(spec=["addCookie", "redirect", "finish"])
        yield defer.ensureDeferred(
            self.handler.handle_redirect_request(req, b"http://client/redirect")
        )
        url = req.redirect.call_args[0][0]
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

    @defer.inlineCallbacks
    def test_callback_error(self):
        self.handler._render_error = Mock()
        request = Mock(args={})
        request.args[b"error"] = [b"invalid_client"]
        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))
        self.handler._render_error.assert_called_once_with(
            request, "invalid_client", ""
        )

        request.args[b"error_description"] = [b"some description"]
        self.handler._render_error.reset_mock()
        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))
        self.handler._render_error.assert_called_once_with(
            request, "invalid_client", "some description"
        )

    @defer.inlineCallbacks
    def test_callback(self):
        token = {
            "type": "bearer",
            "id_token": "id_token",
            "access_token": "access_token",
        }
        userinfo = {
            "sub": "foo",
            "preferred_username": "bar",
        }
        user_id = UserID("foo", "domain.org")
        self.handler._exchange_code = simple_async_mock(return_value=token)
        self.handler._parse_id_token = simple_async_mock(return_value=userinfo)
        self.handler._map_userinfo_to_user = simple_async_mock(return_value=user_id)
        self.handler._auth_handler.complete_sso_login = simple_async_mock()
        request = Mock(spec=["args", "getCookie", "addCookie"])

        code = "code"
        state = "state"
        nonce = "nonce"
        client_redirect_url = "http://client/redirect"
        session = self.handler._macaroon_generator.generate_oidc_session_token(
            state=state, nonce=nonce, client_redirect_url=client_redirect_url,
        )
        request.getCookie.return_value = session

        request.args = {}
        request.args[b"code"] = [code.encode("utf-8")]
        request.args[b"state"] = [state.encode("utf-8")]

        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))

        self.handler._auth_handler.complete_sso_login.assert_called_once_with(
            user_id, request, client_redirect_url,
        )

        self.handler._exchange_code.assert_called_once_with(code)
        self.handler._parse_id_token.assert_called_once_with(token, nonce=nonce)
        self.handler._map_userinfo_to_user.assert_called_once_with(userinfo)

    @defer.inlineCallbacks
    def test_callback_session(self):
        self.handler._render_error = Mock(return_value=None)
        request = Mock(spec=["args", "getCookie", "addCookie"])

        # Missing cookie
        request.args = {}
        request.getCookie.return_value = None
        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("missing_session", "No session cookie found")
        self.handler._render_error.reset_mock()

        # Invalid cookie
        request.args = {}
        request.args[b"state"] = [b"state"]
        request.getCookie.return_value = "session"
        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_session")
        self.handler._render_error.reset_mock()

        # Mismatching session
        session = self.handler._macaroon_generator.generate_oidc_session_token(
            state="state", nonce="nonce", client_redirect_url="http://client/redirect",
        )
        request.args = {}
        request.args[b"state"] = [b"mismatching state"]
        request.getCookie.return_value = session
        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("mismatching_session")
        self.handler._render_error.reset_mock()

        # Valid session
        request.args = {}
        request.args[b"state"] = [b"state"]
        request.getCookie.return_value = session
        yield defer.ensureDeferred(self.handler.handle_oidc_callback(request))
        self.assertRenderedError("invalid_request")
        self.handler._render_error.reset_mock()

    @override_config({"oidc_config": {"client_auth_method": "client_secret_post"}})
    @defer.inlineCallbacks
    def test_exchange_code(self):
        token = {"type": "bearer"}
        token_json = json.dumps(token).encode("utf-8")
        self.http_client.request = simple_async_mock(
            return_value=FakeResponse(code=200, phrase=b"OK", body=token_json)
        )
        code = "code"
        ret = yield defer.ensureDeferred(self.handler._exchange_code(code))
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
        with self.assertRaises(OidcError) as exc:
            yield defer.ensureDeferred(self.handler._exchange_code(code))
        self.assertEqual(exc.exception.error, "foo")
        self.assertEqual(exc.exception.error_description, "bar")
