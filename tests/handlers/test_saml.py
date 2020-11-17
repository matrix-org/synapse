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

from mock import Mock

import attr

from synapse.handlers.saml_handler import SamlHandler
from synapse.handlers.sso import MappingException
from synapse.types import UserID

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
        return {"mxid_localpart": saml_response.ava["username"], "displayname": None}


def simple_async_mock(return_value=None, raises=None):
    # AsyncMock is not available in python3.5, this mimics part of its behaviour
    async def cb(*args, **kwargs):
        if raises:
            raise raises
        return return_value

    return Mock(side_effect=cb)


class SamlHandlerTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        self.http_client = Mock(spec=["get_json"])
        self.http_client.user_agent = "Synapse Test"

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

        # Some providers return an integer ID.
        saml_response = FakeAuthnResponse({"uid": 1234, "username": "test_user_2"})
        mxid = self.get_success(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@test_user_2:test")

        # Test if the mxid is already taken
        store = self.hs.get_datastore()
        user3 = UserID.from_string("@test_user_3:test")
        self.get_success(
            store.register_user(user_id=user3.to_string(), password_hash=None)
        )
        saml_response = FakeAuthnResponse({"uid": "test3", "username": "test_user_3"})
        e = self.get_failure(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            ),
            MappingException,
        )
        self.assertEqual(
            str(e.value), "Unable to generate a Matrix ID from the SAML response"
        )

    def test_map_saml_response_to_invalid_localpart(self):
        """If the mapping provider generates an invalid localpart it should be rejected."""
        saml_response = FakeAuthnResponse({"uid": "test2", "username": "föö"})
        redirect_url = ""
        e = self.get_failure(
            self.handler._map_saml_response_to_user(
                saml_response, redirect_url, "user-agent", "10.10.10.10"
            ),
            MappingException,
        )
        self.assertEqual(str(e.value), "localpart is invalid: föö")
