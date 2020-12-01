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

import attr

from synapse.handlers.saml_handler import SamlHandler
from synapse.handlers.sso import MappingException

from tests.unittest import HomeserverTestCase

# These are a few constants that are used as config parameters in the tests.
BASE_URL = "https://synapse/"


@attr.s
class FakeAuthnResponse:
    ava = attr.ib(type=dict)


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


class SamlHandlerTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["public_baseurl"] = BASE_URL
        saml_config = {
            "sp_config": {"metadata": {}},
            # Disable grandfathering.
            "grandfathered_mxid_source_attribute": None,
            "user_mapping_provider": {"module": __name__ + ".TestMappingProvider"},
        }
        config["saml2_config"] = saml_config

        hs = self.setup_test_homeserver(
            http_client=self.http_client,
            proxied_http_client=self.http_client,
            config=config,
        )

        self.handler = SamlHandler(hs)

        # Reduce the number of attempts when generating MXIDs.
        self.handler._sso_handler._MAP_USERNAME_RETRIES = 3

        return hs

    def test_map_saml_response_to_user(self):
        """Ensure that mapping the SAML response returned from a provider to an MXID works properly."""
        saml_response = FakeAuthnResponse({"uid": "test_user", "username": "test_user"})
        # The redirect_url doesn't matter with the default user mapping provider.
        redirect_url = ""
        mxid = self.get_success(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@test_user:test")

    def test_map_saml_response_to_invalid_localpart(self):
        """If the mapping provider generates an invalid localpart it should be rejected."""
        saml_response = FakeAuthnResponse({"uid": "test", "username": "föö"})
        redirect_url = ""
        e = self.get_failure(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            ),
            MappingException,
        )
        self.assertEqual(str(e.value), "localpart is invalid: föö")

    def test_map_saml_response_to_user_retries(self):
        """The mapping provider can retry generating an MXID if the MXID is already in use."""
        store = self.hs.get_datastore()
        self.get_success(
            store.register_user(user_id="@test_user:test", password_hash=None)
        )
        saml_response = FakeAuthnResponse({"uid": "test", "username": "test_user"})
        redirect_url = ""
        mxid = self.get_success(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            )
        )
        # test_user is already taken, so test_user1 gets registered instead.
        self.assertEqual(mxid, "@test_user1:test")

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
        e = self.get_failure(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            ),
            MappingException,
        )
        self.assertEqual(
            str(e.value), "Unable to generate a Matrix ID from the SSO response"
        )
