#  Copyright 2020 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from typing import Optional

from mock import Mock

import attr

from synapse.api.errors import RedirectException

from tests.test_utils import simple_async_mock
from tests.unittest import HomeserverTestCase, override_config

# Check if we have the dependencies to run the tests.
try:
    import saml2.config
    from saml2.sigver import SigverError

    has_saml2 = True

    # pysaml2 can be installed and imported, but might not be able to find xmlsec1.
    config = saml2.config.SPConfig()
    try:
        config.load({"metadata": {}})
        has_xmlsec1 = True
    except SigverError:
        has_xmlsec1 = False
except ImportError:
    has_saml2 = False
    has_xmlsec1 = False

# These are a few constants that are used as config parameters in the tests.
BASE_URL = "https://synapse/"


@attr.s
class FakeAuthnResponse:
    ava = attr.ib(type=dict)
    assertions = attr.ib(type=list, factory=list)
    in_response_to = attr.ib(type=Optional[str], default=None)


class TestMappingProvider:
    def __init__(self, config, module):
        pass

    @staticmethod
    def parse_config(config):
        return

    @staticmethod
    def get_saml_attributes(config):
        return {"uid"}, {"displayName"}

    def get_remote_user_id(self, saml_response, client_redirect_url):
        return saml_response.ava["uid"]

    def saml_response_to_user_attributes(
        self, saml_response, failures, client_redirect_url
    ):
        localpart = saml_response.ava["username"] + (str(failures) if failures else "")
        return {"mxid_localpart": localpart, "displayname": None}


class TestRedirectMappingProvider(TestMappingProvider):
    def saml_response_to_user_attributes(
        self, saml_response, failures, client_redirect_url
    ):
        raise RedirectException(b"https://custom-saml-redirect/")


class SamlHandlerTestCase(HomeserverTestCase):
    def default_config(self):
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        saml_config = {
            "sp_config": {"metadata": {}},
            # Disable grandfathering.
            "grandfathered_mxid_source_attribute": None,
            "user_mapping_provider": {"module": __name__ + ".TestMappingProvider"},
        }

        # Update this config with what's in the default config so that
        # override_config works as expected.
        saml_config.update(config.get("saml2_config", {}))
        config["saml2_config"] = saml_config

        return config

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()

        self.handler = hs.get_saml_handler()

        # Reduce the number of attempts when generating MXIDs.
        sso_handler = hs.get_sso_handler()
        sso_handler._MAP_USERNAME_RETRIES = 3

        return hs

    if not has_saml2:
        skip = "Requires pysaml2"
    elif not has_xmlsec1:
        skip = "Requires xmlsec1"

    def test_map_saml_response_to_user(self):
        """Ensure that mapping the SAML response returned from a provider to an MXID works properly."""

        # stub out the auth handler
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        # send a mocked-up SAML response to the callback
        saml_response = FakeAuthnResponse({"uid": "test_user", "username": "test_user"})
        request = _mock_request()
        self.get_success(
            self.handler._handle_authn_response(request, saml_response, "redirect_uri")
        )

        # check that the auth handler got called as expected
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user:test", request, "redirect_uri", None
        )

    @override_config({"saml2_config": {"grandfathered_mxid_source_attribute": "mxid"}})
    def test_map_saml_response_to_existing_user(self):
        """Existing users can log in with SAML account."""
        store = self.hs.get_datastore()
        self.get_success(
            store.register_user(user_id="@test_user:test", password_hash=None)
        )

        # stub out the auth handler
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        # Map a user via SSO.
        saml_response = FakeAuthnResponse(
            {"uid": "tester", "mxid": ["test_user"], "username": "test_user"}
        )
        request = _mock_request()
        self.get_success(
            self.handler._handle_authn_response(request, saml_response, "")
        )

        # check that the auth handler got called as expected
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user:test", request, "", None
        )

        # Subsequent calls should map to the same mxid.
        auth_handler.complete_sso_login.reset_mock()
        self.get_success(
            self.handler._handle_authn_response(request, saml_response, "")
        )
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user:test", request, "", None
        )

    def test_map_saml_response_to_invalid_localpart(self):
        """If the mapping provider generates an invalid localpart it should be rejected."""

        # stub out the auth handler
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()

        # mock out the error renderer too
        sso_handler = self.hs.get_sso_handler()
        sso_handler.render_error = Mock(return_value=None)

        saml_response = FakeAuthnResponse({"uid": "test", "username": "föö"})
        request = _mock_request()
        self.get_success(
            self.handler._handle_authn_response(request, saml_response, ""),
        )
        sso_handler.render_error.assert_called_once_with(
            request, "mapping_error", "localpart is invalid: föö"
        )
        auth_handler.complete_sso_login.assert_not_called()

    def test_map_saml_response_to_user_retries(self):
        """The mapping provider can retry generating an MXID if the MXID is already in use."""

        # stub out the auth handler and error renderer
        auth_handler = self.hs.get_auth_handler()
        auth_handler.complete_sso_login = simple_async_mock()
        sso_handler = self.hs.get_sso_handler()
        sso_handler.render_error = Mock(return_value=None)

        # register a user to occupy the first-choice MXID
        store = self.hs.get_datastore()
        self.get_success(
            store.register_user(user_id="@test_user:test", password_hash=None)
        )

        # send the fake SAML response
        saml_response = FakeAuthnResponse({"uid": "test", "username": "test_user"})
        request = _mock_request()
        self.get_success(
            self.handler._handle_authn_response(request, saml_response, ""),
        )

        # test_user is already taken, so test_user1 gets registered instead.
        auth_handler.complete_sso_login.assert_called_once_with(
            "@test_user1:test", request, "", None
        )
        auth_handler.complete_sso_login.reset_mock()

        # Register all of the potential mxids for a particular SAML username.
        self.get_success(
            store.register_user(user_id="@tester:test", password_hash=None)
        )
        for i in range(1, 3):
            self.get_success(
                store.register_user(user_id="@tester%d:test" % i, password_hash=None)
            )

        # Now attempt to map to a username, this will fail since all potential usernames are taken.
        saml_response = FakeAuthnResponse({"uid": "tester", "username": "tester"})
        self.get_success(
            self.handler._handle_authn_response(request, saml_response, ""),
        )
        sso_handler.render_error.assert_called_once_with(
            request,
            "mapping_error",
            "Unable to generate a Matrix ID from the SSO response",
        )
        auth_handler.complete_sso_login.assert_not_called()

    @override_config(
        {
            "saml2_config": {
                "user_mapping_provider": {
                    "module": __name__ + ".TestRedirectMappingProvider"
                },
            }
        }
    )
    def test_map_saml_response_redirect(self):
        """Test a mapping provider that raises a RedirectException"""

        saml_response = FakeAuthnResponse({"uid": "test", "username": "test_user"})
        request = _mock_request()
        e = self.get_failure(
            self.handler._handle_authn_response(request, saml_response, ""),
            RedirectException,
        )
        self.assertEqual(e.value.location, b"https://custom-saml-redirect/")


def _mock_request():
    """Returns a mock which will stand in as a SynapseRequest"""
    return Mock(spec=["getClientIP", "getHeader"])
