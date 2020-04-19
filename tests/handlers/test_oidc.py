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

from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

from mock import Mock

import pymacaroons

from twisted.internet import defer

from synapse.handlers.oidc_handler import OidcHandler

from tests.unittest import HomeserverTestCase, override_config

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

        config = self.default_config()
        config["public_baseurl"] = BASE_URL
        oidc_config = config.get("oidc_config", {})
        oidc_config["enabled"] = True
        oidc_config["client_id"] = CLIENT_ID
        oidc_config["client_secret"] = CLIENT_SECRET
        oidc_config["issuer"] = ISSUER
        oidc_config["scopes"] = SCOPES
        config["oidc_config"] = oidc_config

        hs = self.setup_test_homeserver(
            http_client=self.http_client,
            proxied_http_client=self.http_client,
            config=config,
        )

        self.handler = OidcHandler(hs)

        return hs

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
        req = Mock(spec=["addCookie"])
        url = yield defer.ensureDeferred(
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
        req.addCookie.assert_called_once()
        a = req.addCookie.call_args
        self.assertEqual(a.args[0], COOKIE_NAME)
        self.assertEqual(a.kwargs["path"], COOKIE_PATH)
        cookie = a.args[1]

        macaroon = pymacaroons.Macaroon.deserialize(cookie)
        state = self.handler._get_value_from_macaroon(macaroon, "state")
        nonce = self.handler._get_value_from_macaroon(macaroon, "nonce")
        redirect = self.handler._get_value_from_macaroon(
            macaroon, "client_redirect_url"
        )

        self.assertEqual(params["state"], [state])
        self.assertEqual(params["nonce"], [nonce])
        self.assertEqual(redirect, "http://client/redirect")
