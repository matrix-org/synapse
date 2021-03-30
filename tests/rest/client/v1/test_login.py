# -*- coding: utf-8 -*-
# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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

import time
import urllib.parse
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode

from unittest.mock import Mock

import pymacaroons

from twisted.web.resource import Resource

import synapse.rest.admin
from synapse.appservice import ApplicationService
from synapse.rest.client.v1 import login, logout
from synapse.rest.client.v2_alpha import devices, register
from synapse.rest.client.v2_alpha.account import WhoamiRestServlet
from synapse.rest.synapse.client import build_synapse_client_resource_tree
from synapse.types import create_requester

from tests import unittest
from tests.handlers.test_oidc import HAS_OIDC
from tests.handlers.test_saml import has_saml2
from tests.rest.client.v1.utils import TEST_OIDC_AUTH_ENDPOINT, TEST_OIDC_CONFIG
from tests.test_utils.html_parsers import TestHtmlParser
from tests.unittest import HomeserverTestCase, override_config, skip_unless

try:
    import jwt

    HAS_JWT = True
except ImportError:
    HAS_JWT = False


# synapse server name: used to populate public_baseurl in some tests
SYNAPSE_SERVER_PUBLIC_HOSTNAME = "synapse"

# public_baseurl for some tests. It uses an http:// scheme because
# FakeChannel.isSecure() returns False, so synapse will see the requested uri as
# http://..., so using http in the public_baseurl stops Synapse trying to redirect to
# https://....
BASE_URL = "http://%s/" % (SYNAPSE_SERVER_PUBLIC_HOSTNAME,)

# CAS server used in some tests
CAS_SERVER = "https://fake.test"

# just enough to tell pysaml2 where to redirect to
SAML_SERVER = "https://test.saml.server/idp/sso"
TEST_SAML_METADATA = """
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%(SAML_SERVER)s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
""" % {
    "SAML_SERVER": SAML_SERVER,
}

LOGIN_URL = b"/_matrix/client/r0/login"
TEST_URL = b"/_matrix/client/r0/account/whoami"

# a (valid) url with some annoying characters in.  %3D is =, %26 is &, %2B is +
TEST_CLIENT_REDIRECT_URL = 'https://x?<ab c>&q"+%3D%2B"="fö%26=o"'

# the query params in TEST_CLIENT_REDIRECT_URL
EXPECTED_CLIENT_REDIRECT_URL_PARAMS = [("<ab c>", ""), ('q" =+"', '"fö&=o"')]

# (possibly experimental) login flows we expect to appear in the list after the normal
# ones
ADDITIONAL_LOGIN_FLOWS = [{"type": "uk.half-shot.msc2778.login.application_service"}]


class LoginRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        logout.register_servlets,
        devices.register_servlets,
        lambda hs, http_server: WhoamiRestServlet(hs).register(http_server),
    ]

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        self.hs.config.enable_registration = True
        self.hs.config.registrations_require_3pid = []
        self.hs.config.auto_join_rooms = []
        self.hs.config.enable_registration_captcha = False

        return self.hs

    @override_config(
        {
            "rc_login": {
                "address": {"per_second": 0.17, "burst_count": 5},
                # Prevent the account login ratelimiter from raising first
                #
                # This is normally covered by the default test homeserver config
                # which sets these values to 10000, but as we're overriding the entire
                # rc_login dict here, we need to set this manually as well
                "account": {"per_second": 10000, "burst_count": 10000},
            }
        }
    )
    def test_POST_ratelimiting_per_address(self):
        # Create different users so we're sure not to be bothered by the per-user
        # ratelimiter.
        for i in range(0, 6):
            self.register_user("kermit" + str(i), "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit" + str(i)},
                "password": "monkey",
            }
            channel = self.make_request(b"POST", LOGIN_URL, params)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit" + str(i)},
            "password": "monkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config(
        {
            "rc_login": {
                "account": {"per_second": 0.17, "burst_count": 5},
                # Prevent the address login ratelimiter from raising first
                #
                # This is normally covered by the default test homeserver config
                # which sets these values to 10000, but as we're overriding the entire
                # rc_login dict here, we need to set this manually as well
                "address": {"per_second": 10000, "burst_count": 10000},
            }
        }
    )
    def test_POST_ratelimiting_per_account(self):
        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit"},
                "password": "monkey",
            }
            channel = self.make_request(b"POST", LOGIN_URL, params)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "monkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config(
        {
            "rc_login": {
                # Prevent the address login ratelimiter from raising first
                #
                # This is normally covered by the default test homeserver config
                # which sets these values to 10000, but as we're overriding the entire
                # rc_login dict here, we need to set this manually as well
                "address": {"per_second": 10000, "burst_count": 10000},
                "failed_attempts": {"per_second": 0.17, "burst_count": 5},
            }
        }
    )
    def test_POST_ratelimiting_per_account_failed_attempts(self):
        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit"},
                "password": "notamonkey",
            }
            channel = self.make_request(b"POST", LOGIN_URL, params)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"403", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "notamonkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"403", channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_soft_logout(self):
        self.register_user("kermit", "monkey")

        # we shouldn't be able to make requests without an access token
        channel = self.make_request(b"GET", TEST_URL)
        self.assertEquals(channel.result["code"], b"401", channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_MISSING_TOKEN")

        # log in as normal
        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "monkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.code, 200, channel.result)
        access_token = channel.json_body["access_token"]
        device_id = channel.json_body["device_id"]

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        #
        # test behaviour after deleting the expired device
        #

        # we now log in as a different device
        access_token_2 = self.login("kermit", "monkey")

        # more requests with the expired token should still return a soft-logout
        self.reactor.advance(3600)
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # ... but if we delete that device, it will be a proper logout
        self._delete_device(access_token_2, "kermit", "monkey", device_id)

        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], False)

    def _delete_device(self, access_token, user_id, password, device_id):
        """Perform the UI-Auth to delete a device"""
        channel = self.make_request(
            b"DELETE", "devices/" + device_id, access_token=access_token
        )
        self.assertEquals(channel.code, 401, channel.result)
        # check it's a UI-Auth fail
        self.assertEqual(
            set(channel.json_body.keys()),
            {"flows", "params", "session"},
            channel.result,
        )

        auth = {
            "type": "m.login.password",
            # https://github.com/matrix-org/synapse/issues/5665
            # "identifier": {"type": "m.id.user", "user": user_id},
            "user": user_id,
            "password": password,
            "session": channel.json_body["session"],
        }

        channel = self.make_request(
            b"DELETE",
            "devices/" + device_id,
            access_token=access_token,
            content={"auth": auth},
        )
        self.assertEquals(channel.code, 200, channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_session_can_hard_logout_after_being_soft_logged_out(self):
        self.register_user("kermit", "monkey")

        # log in as normal
        access_token = self.login("kermit", "monkey")

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # Now try to hard logout this session
        channel = self.make_request(b"POST", "/logout", access_token=access_token)
        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_session_can_hard_logout_all_sessions_after_being_soft_logged_out(self):
        self.register_user("kermit", "monkey")

        # log in as normal
        access_token = self.login("kermit", "monkey")

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # Now try to hard log out all of the user's sessions
        channel = self.make_request(b"POST", "/logout/all", access_token=access_token)
        self.assertEquals(channel.result["code"], b"200", channel.result)


@skip_unless(has_saml2 and HAS_OIDC, "Requires SAML2 and OIDC")
class MultiSSOTestCase(unittest.HomeserverTestCase):
    """Tests for homeservers with multiple SSO providers enabled"""

    servlets = [
        login.register_servlets,
    ]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()

        config["public_baseurl"] = BASE_URL

        config["cas_config"] = {
            "enabled": True,
            "server_url": CAS_SERVER,
            "service_url": "https://matrix.goodserver.com:8448",
        }

        config["saml2_config"] = {
            "sp_config": {
                "metadata": {"inline": [TEST_SAML_METADATA]},
                # use the XMLSecurity backend to avoid relying on xmlsec1
                "crypto_backend": "XMLSecurity",
            },
        }

        # default OIDC provider
        config["oidc_config"] = TEST_OIDC_CONFIG

        # additional OIDC providers
        config["oidc_providers"] = [
            {
                "idp_id": "idp1",
                "idp_name": "IDP1",
                "discover": False,
                "issuer": "https://issuer1",
                "client_id": "test-client-id",
                "client_secret": "test-client-secret",
                "scopes": ["profile"],
                "authorization_endpoint": "https://issuer1/auth",
                "token_endpoint": "https://issuer1/token",
                "userinfo_endpoint": "https://issuer1/userinfo",
                "user_mapping_provider": {
                    "config": {"localpart_template": "{{ user.sub }}"}
                },
            }
        ]
        return config

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d.update(build_synapse_client_resource_tree(self.hs))
        return d

    def test_get_login_flows(self):
        """GET /login should return password and SSO flows"""
        channel = self.make_request("GET", "/_matrix/client/r0/login")
        self.assertEqual(channel.code, 200, channel.result)

        expected_flow_types = [
            "m.login.cas",
            "m.login.sso",
            "m.login.token",
            "m.login.password",
        ] + [f["type"] for f in ADDITIONAL_LOGIN_FLOWS]

        self.assertCountEqual(
            [f["type"] for f in channel.json_body["flows"]], expected_flow_types
        )

    @override_config({"experimental_features": {"msc2858_enabled": True}})
    def test_get_msc2858_login_flows(self):
        """The SSO flow should include IdP info if MSC2858 is enabled"""
        channel = self.make_request("GET", "/_matrix/client/r0/login")
        self.assertEqual(channel.code, 200, channel.result)

        # stick the flows results in a dict by type
        flow_results = {}  # type: Dict[str, Any]
        for f in channel.json_body["flows"]:
            flow_type = f["type"]
            self.assertNotIn(
                flow_type, flow_results, "duplicate flow type %s" % (flow_type,)
            )
            flow_results[flow_type] = f

        self.assertIn("m.login.sso", flow_results, "m.login.sso was not returned")
        sso_flow = flow_results.pop("m.login.sso")
        # we should have a set of IdPs
        self.assertCountEqual(
            sso_flow["org.matrix.msc2858.identity_providers"],
            [
                {"id": "cas", "name": "CAS"},
                {"id": "saml", "name": "SAML"},
                {"id": "oidc-idp1", "name": "IDP1"},
                {"id": "oidc", "name": "OIDC"},
            ],
        )

        # the rest of the flows are simple
        expected_flows = [
            {"type": "m.login.cas"},
            {"type": "m.login.token"},
            {"type": "m.login.password"},
        ] + ADDITIONAL_LOGIN_FLOWS

        self.assertCountEqual(flow_results.values(), expected_flows)

    def test_multi_sso_redirect(self):
        """/login/sso/redirect should redirect to an identity picker"""
        # first hit the redirect url, which should redirect to our idp picker
        channel = self._make_sso_redirect_request(False, None)
        self.assertEqual(channel.code, 302, channel.result)
        uri = channel.headers.getRawHeaders("Location")[0]

        # hitting that picker should give us some HTML
        channel = self.make_request("GET", uri)
        self.assertEqual(channel.code, 200, channel.result)

        # parse the form to check it has fields assumed elsewhere in this class
        html = channel.result["body"].decode("utf-8")
        p = TestHtmlParser()
        p.feed(html)
        p.close()

        # there should be a link for each href
        returned_idps = []  # type: List[str]
        for link in p.links:
            path, query = link.split("?", 1)
            self.assertEqual(path, "pick_idp")
            params = urllib.parse.parse_qs(query)
            self.assertEqual(params["redirectUrl"], [TEST_CLIENT_REDIRECT_URL])
            returned_idps.append(params["idp"][0])

        self.assertCountEqual(returned_idps, ["cas", "oidc", "oidc-idp1", "saml"])

    def test_multi_sso_redirect_to_cas(self):
        """If CAS is chosen, should redirect to the CAS server"""

        channel = self.make_request(
            "GET",
            "/_synapse/client/pick_idp?redirectUrl="
            + urllib.parse.quote_plus(TEST_CLIENT_REDIRECT_URL)
            + "&idp=cas",
            shorthand=False,
        )
        self.assertEqual(channel.code, 302, channel.result)
        location_headers = channel.headers.getRawHeaders("Location")
        assert location_headers
        cas_uri = location_headers[0]
        cas_uri_path, cas_uri_query = cas_uri.split("?", 1)

        # it should redirect us to the login page of the cas server
        self.assertEqual(cas_uri_path, CAS_SERVER + "/login")

        # check that the redirectUrl is correctly encoded in the service param - ie, the
        # place that CAS will redirect to
        cas_uri_params = urllib.parse.parse_qs(cas_uri_query)
        service_uri = cas_uri_params["service"][0]
        _, service_uri_query = service_uri.split("?", 1)
        service_uri_params = urllib.parse.parse_qs(service_uri_query)
        self.assertEqual(service_uri_params["redirectUrl"][0], TEST_CLIENT_REDIRECT_URL)

    def test_multi_sso_redirect_to_saml(self):
        """If SAML is chosen, should redirect to the SAML server"""
        channel = self.make_request(
            "GET",
            "/_synapse/client/pick_idp?redirectUrl="
            + urllib.parse.quote_plus(TEST_CLIENT_REDIRECT_URL)
            + "&idp=saml",
        )
        self.assertEqual(channel.code, 302, channel.result)
        location_headers = channel.headers.getRawHeaders("Location")
        assert location_headers
        saml_uri = location_headers[0]
        saml_uri_path, saml_uri_query = saml_uri.split("?", 1)

        # it should redirect us to the login page of the SAML server
        self.assertEqual(saml_uri_path, SAML_SERVER)

        # the RelayState is used to carry the client redirect url
        saml_uri_params = urllib.parse.parse_qs(saml_uri_query)
        relay_state_param = saml_uri_params["RelayState"][0]
        self.assertEqual(relay_state_param, TEST_CLIENT_REDIRECT_URL)

    def test_login_via_oidc(self):
        """If OIDC is chosen, should redirect to the OIDC auth endpoint"""

        # pick the default OIDC provider
        channel = self.make_request(
            "GET",
            "/_synapse/client/pick_idp?redirectUrl="
            + urllib.parse.quote_plus(TEST_CLIENT_REDIRECT_URL)
            + "&idp=oidc",
        )
        self.assertEqual(channel.code, 302, channel.result)
        location_headers = channel.headers.getRawHeaders("Location")
        assert location_headers
        oidc_uri = location_headers[0]
        oidc_uri_path, oidc_uri_query = oidc_uri.split("?", 1)

        # it should redirect us to the auth page of the OIDC server
        self.assertEqual(oidc_uri_path, TEST_OIDC_AUTH_ENDPOINT)

        # ... and should have set a cookie including the redirect url
        cookie_headers = channel.headers.getRawHeaders("Set-Cookie")
        assert cookie_headers
        cookies = {}  # type: Dict[str, str]
        for h in cookie_headers:
            key, value = h.split(";")[0].split("=", maxsplit=1)
            cookies[key] = value

        oidc_session_cookie = cookies["oidc_session"]
        macaroon = pymacaroons.Macaroon.deserialize(oidc_session_cookie)
        self.assertEqual(
            self._get_value_from_macaroon(macaroon, "client_redirect_url"),
            TEST_CLIENT_REDIRECT_URL,
        )

        channel = self.helper.complete_oidc_auth(oidc_uri, cookies, {"sub": "user1"})

        # that should serve a confirmation page
        self.assertEqual(channel.code, 200, channel.result)
        content_type_headers = channel.headers.getRawHeaders("Content-Type")
        assert content_type_headers
        self.assertTrue(content_type_headers[-1].startswith("text/html"))
        p = TestHtmlParser()
        p.feed(channel.text_body)
        p.close()

        # ... which should contain our redirect link
        self.assertEqual(len(p.links), 1)
        path, query = p.links[0].split("?", 1)
        self.assertEqual(path, "https://x")

        # it will have url-encoded the params properly, so we'll have to parse them
        params = urllib.parse.parse_qsl(
            query, keep_blank_values=True, strict_parsing=True, errors="strict"
        )
        self.assertEqual(params[0:2], EXPECTED_CLIENT_REDIRECT_URL_PARAMS)
        self.assertEqual(params[2][0], "loginToken")

        # finally, submit the matrix login token to the login API, which gives us our
        # matrix access token, mxid, and device id.
        login_token = params[2][1]
        chan = self.make_request(
            "POST",
            "/login",
            content={"type": "m.login.token", "token": login_token},
        )
        self.assertEqual(chan.code, 200, chan.result)
        self.assertEqual(chan.json_body["user_id"], "@user1:test")

    def test_multi_sso_redirect_to_unknown(self):
        """An unknown IdP should cause a 400"""
        channel = self.make_request(
            "GET",
            "/_synapse/client/pick_idp?redirectUrl=http://x&idp=xyz",
        )
        self.assertEqual(channel.code, 400, channel.result)

    def test_client_idp_redirect_to_unknown(self):
        """If the client tries to pick an unknown IdP, return a 404"""
        channel = self._make_sso_redirect_request(False, "xxx")
        self.assertEqual(channel.code, 404, channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_NOT_FOUND")

    def test_client_idp_redirect_to_oidc(self):
        """If the client pick a known IdP, redirect to it"""
        channel = self._make_sso_redirect_request(False, "oidc")
        self.assertEqual(channel.code, 302, channel.result)
        oidc_uri = channel.headers.getRawHeaders("Location")[0]
        oidc_uri_path, oidc_uri_query = oidc_uri.split("?", 1)

        # it should redirect us to the auth page of the OIDC server
        self.assertEqual(oidc_uri_path, TEST_OIDC_AUTH_ENDPOINT)

    @override_config({"experimental_features": {"msc2858_enabled": True}})
    def test_client_msc2858_redirect_to_oidc(self):
        """Test the unstable API"""
        channel = self._make_sso_redirect_request(True, "oidc")
        self.assertEqual(channel.code, 302, channel.result)
        oidc_uri = channel.headers.getRawHeaders("Location")[0]
        oidc_uri_path, oidc_uri_query = oidc_uri.split("?", 1)

        # it should redirect us to the auth page of the OIDC server
        self.assertEqual(oidc_uri_path, TEST_OIDC_AUTH_ENDPOINT)

    def test_client_idp_redirect_msc2858_disabled(self):
        """If the client tries to use the MSC2858 endpoint but MSC2858 is disabled, return a 400"""
        channel = self._make_sso_redirect_request(True, "oidc")
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")

    def _make_sso_redirect_request(
        self, unstable_endpoint: bool = False, idp_prov: Optional[str] = None
    ):
        """Send a request to /_matrix/client/r0/login/sso/redirect

        ... or the unstable equivalent

        ... possibly specifying an IDP provider
        """
        endpoint = (
            "/_matrix/client/unstable/org.matrix.msc2858/login/sso/redirect"
            if unstable_endpoint
            else "/_matrix/client/r0/login/sso/redirect"
        )
        if idp_prov is not None:
            endpoint += "/" + idp_prov
        endpoint += "?redirectUrl=" + urllib.parse.quote_plus(TEST_CLIENT_REDIRECT_URL)

        return self.make_request(
            "GET",
            endpoint,
            custom_headers=[("Host", SYNAPSE_SERVER_PUBLIC_HOSTNAME)],
        )

    @staticmethod
    def _get_value_from_macaroon(macaroon: pymacaroons.Macaroon, key: str) -> str:
        prefix = key + " = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(prefix):
                return caveat.caveat_id[len(prefix) :]
        raise ValueError("No %s caveat in macaroon" % (key,))


class CASTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        self.base_url = "https://matrix.goodserver.com/"
        self.redirect_path = "_synapse/client/login/sso/redirect/confirm"

        config = self.default_config()
        config["public_baseurl"] = (
            config.get("public_baseurl") or "https://matrix.goodserver.com:8448"
        )
        config["cas_config"] = {
            "enabled": True,
            "server_url": CAS_SERVER,
        }

        cas_user_id = "username"
        self.user_id = "@%s:test" % cas_user_id

        async def get_raw(uri, args):
            """Return an example response payload from a call to the `/proxyValidate`
            endpoint of a CAS server, copied from
            https://apereo.github.io/cas/5.0.x/protocol/CAS-Protocol-V2-Specification.html#26-proxyvalidate-cas-20

            This needs to be returned by an async function (as opposed to set as the
            mock's return value) because the corresponding Synapse code awaits on it.
            """
            return (
                """
                <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                  <cas:authenticationSuccess>
                      <cas:user>%s</cas:user>
                      <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...</cas:proxyGrantingTicket>
                      <cas:proxies>
                          <cas:proxy>https://proxy2/pgtUrl</cas:proxy>
                          <cas:proxy>https://proxy1/pgtUrl</cas:proxy>
                      </cas:proxies>
                  </cas:authenticationSuccess>
                </cas:serviceResponse>
            """
                % cas_user_id
            ).encode("utf-8")

        mocked_http_client = Mock(spec=["get_raw"])
        mocked_http_client.get_raw.side_effect = get_raw

        self.hs = self.setup_test_homeserver(
            config=config,
            proxied_http_client=mocked_http_client,
        )

        return self.hs

    def prepare(self, reactor, clock, hs):
        self.deactivate_account_handler = hs.get_deactivate_account_handler()

    def test_cas_redirect_confirm(self):
        """Tests that the SSO login flow serves a confirmation page before redirecting a
        user to the redirect URL.
        """
        base_url = "/_matrix/client/r0/login/cas/ticket?redirectUrl"
        redirect_url = "https://dodgy-site.com/"

        url_parts = list(urllib.parse.urlparse(base_url))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        query.update({"redirectUrl": redirect_url})
        query.update({"ticket": "ticket"})
        url_parts[4] = urllib.parse.urlencode(query)
        cas_ticket_url = urllib.parse.urlunparse(url_parts)

        # Get Synapse to call the fake CAS and serve the template.
        channel = self.make_request("GET", cas_ticket_url)

        # Test that the response is HTML.
        self.assertEqual(channel.code, 200, channel.result)
        content_type_header_value = ""
        for header in channel.result.get("headers", []):
            if header[0] == b"Content-Type":
                content_type_header_value = header[1].decode("utf8")

        self.assertTrue(content_type_header_value.startswith("text/html"))

        # Test that the body isn't empty.
        self.assertTrue(len(channel.result["body"]) > 0)

        # And that it contains our redirect link
        self.assertIn(redirect_url, channel.result["body"].decode("UTF-8"))

    @override_config(
        {
            "sso": {
                "client_whitelist": [
                    "https://legit-site.com/",
                    "https://other-site.com/",
                ]
            }
        }
    )
    def test_cas_redirect_whitelisted(self):
        """Tests that the SSO login flow serves a redirect to a whitelisted url"""
        self._test_redirect("https://legit-site.com/")

    @override_config({"public_baseurl": "https://example.com"})
    def test_cas_redirect_login_fallback(self):
        self._test_redirect("https://example.com/_matrix/static/client/login")

    def _test_redirect(self, redirect_url):
        """Tests that the SSO login flow serves a redirect for the given redirect URL."""
        cas_ticket_url = (
            "/_matrix/client/r0/login/cas/ticket?redirectUrl=%s&ticket=ticket"
            % (urllib.parse.quote(redirect_url))
        )

        # Get Synapse to call the fake CAS and serve the template.
        channel = self.make_request("GET", cas_ticket_url)

        self.assertEqual(channel.code, 302)
        location_headers = channel.headers.getRawHeaders("Location")
        assert location_headers
        self.assertEqual(location_headers[0][: len(redirect_url)], redirect_url)

    @override_config({"sso": {"client_whitelist": ["https://legit-site.com/"]}})
    def test_deactivated_user(self):
        """Logging in as a deactivated account should error."""
        redirect_url = "https://legit-site.com/"

        # First login (to create the user).
        self._test_redirect(redirect_url)

        # Deactivate the account.
        self.get_success(
            self.deactivate_account_handler.deactivate_account(
                self.user_id, False, create_requester(self.user_id)
            )
        )

        # Request the CAS ticket.
        cas_ticket_url = (
            "/_matrix/client/r0/login/cas/ticket?redirectUrl=%s&ticket=ticket"
            % (urllib.parse.quote(redirect_url))
        )

        # Get Synapse to call the fake CAS and serve the template.
        channel = self.make_request("GET", cas_ticket_url)

        # Because the user is deactivated they are served an error template.
        self.assertEqual(channel.code, 403)
        self.assertIn(b"SSO account deactivated", channel.result["body"])


@skip_unless(HAS_JWT, "requires jwt")
class JWTTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
    ]

    jwt_secret = "secret"
    jwt_algorithm = "HS256"

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        self.hs.config.jwt_enabled = True
        self.hs.config.jwt_secret = self.jwt_secret
        self.hs.config.jwt_algorithm = self.jwt_algorithm
        return self.hs

    def jwt_encode(self, payload: Dict[str, Any], secret: str = jwt_secret) -> str:
        # PyJWT 2.0.0 changed the return type of jwt.encode from bytes to str.
        result = jwt.encode(
            payload, secret, self.jwt_algorithm
        )  # type: Union[str, bytes]
        if isinstance(result, bytes):
            return result.decode("ascii")
        return result

    def jwt_login(self, *args):
        params = {"type": "org.matrix.login.jwt", "token": self.jwt_encode(*args)}
        channel = self.make_request(b"POST", LOGIN_URL, params)
        return channel

    def test_login_jwt_valid_registered(self):
        self.register_user("kermit", "monkey")
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

    def test_login_jwt_valid_unregistered(self):
        channel = self.jwt_login({"sub": "frog"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@frog:test")

    def test_login_jwt_invalid_signature(self):
        channel = self.jwt_login({"sub": "frog"}, "notsecret")
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            "JWT validation failed: Signature verification failed",
        )

    def test_login_jwt_expired(self):
        channel = self.jwt_login({"sub": "frog", "exp": 864000})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Signature has expired"
        )

    def test_login_jwt_not_before(self):
        now = int(time.time())
        channel = self.jwt_login({"sub": "frog", "nbf": now + 3600})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            "JWT validation failed: The token is not yet valid (nbf)",
        )

    def test_login_no_sub(self):
        channel = self.jwt_login({"username": "root"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(channel.json_body["error"], "Invalid JWT")

    @override_config(
        {
            "jwt_config": {
                "jwt_enabled": True,
                "secret": jwt_secret,
                "algorithm": jwt_algorithm,
                "issuer": "test-issuer",
            }
        }
    )
    def test_login_iss(self):
        """Test validating the issuer claim."""
        # A valid issuer.
        channel = self.jwt_login({"sub": "kermit", "iss": "test-issuer"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

        # An invalid issuer.
        channel = self.jwt_login({"sub": "kermit", "iss": "invalid"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Invalid issuer"
        )

        # Not providing an issuer.
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            'JWT validation failed: Token is missing the "iss" claim',
        )

    def test_login_iss_no_config(self):
        """Test providing an issuer claim without requiring it in the configuration."""
        channel = self.jwt_login({"sub": "kermit", "iss": "invalid"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

    @override_config(
        {
            "jwt_config": {
                "jwt_enabled": True,
                "secret": jwt_secret,
                "algorithm": jwt_algorithm,
                "audiences": ["test-audience"],
            }
        }
    )
    def test_login_aud(self):
        """Test validating the audience claim."""
        # A valid audience.
        channel = self.jwt_login({"sub": "kermit", "aud": "test-audience"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

        # An invalid audience.
        channel = self.jwt_login({"sub": "kermit", "aud": "invalid"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Invalid audience"
        )

        # Not providing an audience.
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            'JWT validation failed: Token is missing the "aud" claim',
        )

    def test_login_aud_no_config(self):
        """Test providing an audience without requiring it in the configuration."""
        channel = self.jwt_login({"sub": "kermit", "aud": "invalid"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Invalid audience"
        )

    def test_login_no_token(self):
        params = {"type": "org.matrix.login.jwt"}
        channel = self.make_request(b"POST", LOGIN_URL, params)
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(channel.json_body["error"], "Token field for JWT is missing")


# The JWTPubKeyTestCase is a complement to JWTTestCase where we instead use
# RSS256, with a public key configured in synapse as "jwt_secret", and tokens
# signed by the private key.
@skip_unless(HAS_JWT, "requires jwt")
class JWTPubKeyTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
    ]

    # This key's pubkey is used as the jwt_secret setting of synapse. Valid
    # tokens are signed by this and validated using the pubkey. It is generated
    # with `openssl genrsa 512` (not a secure way to generate real keys, but
    # good enough for tests!)
    jwt_privatekey = "\n".join(
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIBPAIBAAJBAM50f1Q5gsdmzifLstzLHb5NhfajiOt7TKO1vSEWdq7u9x8SMFiB",
            "492RM9W/XFoh8WUfL9uL6Now6tPRDsWv3xsCAwEAAQJAUv7OOSOtiU+wzJq82rnk",
            "yR4NHqt7XX8BvkZPM7/+EjBRanmZNSp5kYZzKVaZ/gTOM9+9MwlmhidrUOweKfB/",
            "kQIhAPZwHazbjo7dYlJs7wPQz1vd+aHSEH+3uQKIysebkmm3AiEA1nc6mDdmgiUq",
            "TpIN8A4MBKmfZMWTLq6z05y/qjKyxb0CIQDYJxCwTEenIaEa4PdoJl+qmXFasVDN",
            "ZU0+XtNV7yul0wIhAMI9IhiStIjS2EppBa6RSlk+t1oxh2gUWlIh+YVQfZGRAiEA",
            "tqBR7qLZGJ5CVKxWmNhJZGt1QHoUtOch8t9C4IdOZ2g=",
            "-----END RSA PRIVATE KEY-----",
        ]
    )

    # Generated with `openssl rsa -in foo.key -pubout`, with the the above
    # private key placed in foo.key (jwt_privatekey).
    jwt_pubkey = "\n".join(
        [
            "-----BEGIN PUBLIC KEY-----",
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM50f1Q5gsdmzifLstzLHb5NhfajiOt7",
            "TKO1vSEWdq7u9x8SMFiB492RM9W/XFoh8WUfL9uL6Now6tPRDsWv3xsCAwEAAQ==",
            "-----END PUBLIC KEY-----",
        ]
    )

    # This key is used to sign tokens that shouldn't be accepted by synapse.
    # Generated just like jwt_privatekey.
    bad_privatekey = "\n".join(
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIBOgIBAAJBAL//SQrKpKbjCCnv/FlasJCv+t3k/MPsZfniJe4DVFhsktF2lwQv",
            "gLjmQD3jBUTz+/FndLSBvr3F4OHtGL9O/osCAwEAAQJAJqH0jZJW7Smzo9ShP02L",
            "R6HRZcLExZuUrWI+5ZSP7TaZ1uwJzGFspDrunqaVoPobndw/8VsP8HFyKtceC7vY",
            "uQIhAPdYInDDSJ8rFKGiy3Ajv5KWISBicjevWHF9dbotmNO9AiEAxrdRJVU+EI9I",
            "eB4qRZpY6n4pnwyP0p8f/A3NBaQPG+cCIFlj08aW/PbxNdqYoBdeBA0xDrXKfmbb",
            "iwYxBkwL0JCtAiBYmsi94sJn09u2Y4zpuCbJeDPKzWkbuwQh+W1fhIWQJQIhAKR0",
            "KydN6cRLvphNQ9c/vBTdlzWxzcSxREpguC7F1J1m",
            "-----END RSA PRIVATE KEY-----",
        ]
    )

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        self.hs.config.jwt_enabled = True
        self.hs.config.jwt_secret = self.jwt_pubkey
        self.hs.config.jwt_algorithm = "RS256"
        return self.hs

    def jwt_encode(self, payload: Dict[str, Any], secret: str = jwt_privatekey) -> str:
        # PyJWT 2.0.0 changed the return type of jwt.encode from bytes to str.
        result = jwt.encode(payload, secret, "RS256")  # type: Union[bytes,str]
        if isinstance(result, bytes):
            return result.decode("ascii")
        return result

    def jwt_login(self, *args):
        params = {"type": "org.matrix.login.jwt", "token": self.jwt_encode(*args)}
        channel = self.make_request(b"POST", LOGIN_URL, params)
        return channel

    def test_login_jwt_valid(self):
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

    def test_login_jwt_invalid_signature(self):
        channel = self.jwt_login({"sub": "frog"}, self.bad_privatekey)
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            "JWT validation failed: Signature verification failed",
        )


AS_USER = "as_user_alice"


class AppserviceLoginRestServletTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        register.register_servlets,
    ]

    def register_as_user(self, username):
        self.make_request(
            b"POST",
            "/_matrix/client/r0/register?access_token=%s" % (self.service.token,),
            {"username": username},
        )

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()

        self.service = ApplicationService(
            id="unique_identifier",
            token="some_token",
            hostname="example.com",
            sender="@asbot:example.com",
            namespaces={
                ApplicationService.NS_USERS: [
                    {"regex": r"@as_user.*", "exclusive": False}
                ],
                ApplicationService.NS_ROOMS: [],
                ApplicationService.NS_ALIASES: [],
            },
        )
        self.another_service = ApplicationService(
            id="another__identifier",
            token="another_token",
            hostname="example.com",
            sender="@as2bot:example.com",
            namespaces={
                ApplicationService.NS_USERS: [
                    {"regex": r"@as2_user.*", "exclusive": False}
                ],
                ApplicationService.NS_ROOMS: [],
                ApplicationService.NS_ALIASES: [],
            },
        )

        self.hs.get_datastore().services_cache.append(self.service)
        self.hs.get_datastore().services_cache.append(self.another_service)
        return self.hs

    def test_login_appservice_user(self):
        """Test that an appservice user can use /login"""
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": AS_USER},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.service.token
        )

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_login_appservice_user_bot(self):
        """Test that the appservice bot can use /login"""
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": self.service.sender},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.service.token
        )

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_login_appservice_wrong_user(self):
        """Test that non-as users cannot login with the as token"""
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": "fibble_wibble"},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.service.token
        )

        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_login_appservice_wrong_as(self):
        """Test that as users cannot login with wrong as token"""
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": AS_USER},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.another_service.token
        )

        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_login_appservice_no_token(self):
        """Test that users must provide a token when using the appservice
        login method
        """
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": AS_USER},
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"401", channel.result)


@skip_unless(HAS_OIDC, "requires OIDC")
class UsernamePickerTestCase(HomeserverTestCase):
    """Tests for the username picker flow of SSO login"""

    servlets = [login.register_servlets]

    def default_config(self):
        config = super().default_config()
        config["public_baseurl"] = BASE_URL

        config["oidc_config"] = {}
        config["oidc_config"].update(TEST_OIDC_CONFIG)
        config["oidc_config"]["user_mapping_provider"] = {
            "config": {"display_name_template": "{{ user.displayname }}"}
        }

        # whitelist this client URI so we redirect straight to it rather than
        # serving a confirmation page
        config["sso"] = {"client_whitelist": ["https://x"]}
        return config

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d.update(build_synapse_client_resource_tree(self.hs))
        return d

    def test_username_picker(self):
        """Test the happy path of a username picker flow."""

        # do the start of the login flow
        channel = self.helper.auth_via_oidc(
            {"sub": "tester", "displayname": "Jonny"}, TEST_CLIENT_REDIRECT_URL
        )

        # that should redirect to the username picker
        self.assertEqual(channel.code, 302, channel.result)
        location_headers = channel.headers.getRawHeaders("Location")
        assert location_headers
        picker_url = location_headers[0]
        self.assertEqual(picker_url, "/_synapse/client/pick_username/account_details")

        # ... with a username_mapping_session cookie
        cookies = {}  # type: Dict[str,str]
        channel.extract_cookies(cookies)
        self.assertIn("username_mapping_session", cookies)
        session_id = cookies["username_mapping_session"]

        # introspect the sso handler a bit to check that the username mapping session
        # looks ok.
        username_mapping_sessions = self.hs.get_sso_handler()._username_mapping_sessions
        self.assertIn(
            session_id,
            username_mapping_sessions,
            "session id not found in map",
        )
        session = username_mapping_sessions[session_id]
        self.assertEqual(session.remote_user_id, "tester")
        self.assertEqual(session.display_name, "Jonny")
        self.assertEqual(session.client_redirect_url, TEST_CLIENT_REDIRECT_URL)

        # the expiry time should be about 15 minutes away
        expected_expiry = self.clock.time_msec() + (15 * 60 * 1000)
        self.assertApproximates(session.expiry_time_ms, expected_expiry, tolerance=1000)

        # Now, submit a username to the username picker, which should serve a redirect
        # to the completion page
        content = urlencode({b"username": b"bobby"}).encode("utf8")
        chan = self.make_request(
            "POST",
            path=picker_url,
            content=content,
            content_is_form=True,
            custom_headers=[
                ("Cookie", "username_mapping_session=" + session_id),
                # old versions of twisted don't do form-parsing without a valid
                # content-length header.
                ("Content-Length", str(len(content))),
            ],
        )
        self.assertEqual(chan.code, 302, chan.result)
        location_headers = chan.headers.getRawHeaders("Location")
        assert location_headers

        # send a request to the completion page, which should 302 to the client redirectUrl
        chan = self.make_request(
            "GET",
            path=location_headers[0],
            custom_headers=[("Cookie", "username_mapping_session=" + session_id)],
        )
        self.assertEqual(chan.code, 302, chan.result)
        location_headers = chan.headers.getRawHeaders("Location")
        assert location_headers

        # ensure that the returned location matches the requested redirect URL
        path, query = location_headers[0].split("?", 1)
        self.assertEqual(path, "https://x")

        # it will have url-encoded the params properly, so we'll have to parse them
        params = urllib.parse.parse_qsl(
            query, keep_blank_values=True, strict_parsing=True, errors="strict"
        )
        self.assertEqual(params[0:2], EXPECTED_CLIENT_REDIRECT_URL_PARAMS)
        self.assertEqual(params[2][0], "loginToken")

        # fish the login token out of the returned redirect uri
        login_token = params[2][1]

        # finally, submit the matrix login token to the login API, which gives us our
        # matrix access token, mxid, and device id.
        chan = self.make_request(
            "POST",
            "/login",
            content={"type": "m.login.token", "token": login_token},
        )
        self.assertEqual(chan.code, 200, chan.result)
        self.assertEqual(chan.json_body["user_id"], "@bobby:test")
