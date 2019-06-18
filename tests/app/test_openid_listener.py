# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
from mock import Mock, patch

from parameterized import parameterized

from synapse.app.federation_reader import FederationReaderServer
from synapse.app.homeserver import SynapseHomeServer

from tests.unittest import HomeserverTestCase


class FederationReaderOpenIDListenerTests(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(
            http_client=None, homeserverToUse=FederationReaderServer
        )
        return hs

    @parameterized.expand(
        [
            (["federation"], "auth_fail"),
            ([], "no_resource"),
            (["openid", "federation"], "auth_fail"),
            (["openid"], "auth_fail"),
        ]
    )
    def test_openid_listener(self, names, expectation):
        """
        Test different openid listener configurations.

        401 is success here since it means we hit the handler and auth failed.
        """
        config = {
            "port": 8080,
            "bind_addresses": ["0.0.0.0"],
            "resources": [{"names": names}],
        }

        # Listen with the config
        self.hs._listen_http(config)

        # Grab the resource from the site that was told to listen
        site = self.reactor.tcpServers[0][1]
        try:
            self.resource = site.resource.children[b"_matrix"].children[b"federation"]
        except KeyError:
            if expectation == "no_resource":
                return
            raise

        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/openid/userinfo"
        )
        self.render(request)

        self.assertEqual(channel.code, 401)


@patch("synapse.app.homeserver.KeyApiV2Resource", new=Mock())
class SynapseHomeserverOpenIDListenerTests(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(
            http_client=None, homeserverToUse=SynapseHomeServer
        )
        return hs

    @parameterized.expand(
        [
            (["federation"], "auth_fail"),
            ([], "no_resource"),
            (["openid", "federation"], "auth_fail"),
            (["openid"], "auth_fail"),
        ]
    )
    def test_openid_listener(self, names, expectation):
        """
        Test different openid listener configurations.

        401 is success here since it means we hit the handler and auth failed.
        """
        config = {
            "port": 8080,
            "bind_addresses": ["0.0.0.0"],
            "resources": [{"names": names}],
        }

        # Listen with the config
        self.hs._listener_http(config, config)

        # Grab the resource from the site that was told to listen
        site = self.reactor.tcpServers[0][1]
        try:
            self.resource = site.resource.children[b"_matrix"].children[b"federation"]
        except KeyError:
            if expectation == "no_resource":
                return
            raise

        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/openid/userinfo"
        )
        self.render(request)

        self.assertEqual(channel.code, 401)
