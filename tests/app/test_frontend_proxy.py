# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.app.generic_worker import GenericWorkerServer

from tests.unittest import HomeserverTestCase


class FrontendProxyTests(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(
            http_client=None, homeserverToUse=GenericWorkerServer
        )

        return hs

    def default_config(self):
        c = super().default_config()
        c["worker_app"] = "synapse.app.frontend_proxy"

        c["worker_listeners"] = [
            {
                "type": "http",
                "port": 8080,
                "bind_addresses": ["0.0.0.0"],
                "resources": [{"names": ["client"]}],
            }
        ]

        return c

    def test_listen_http_with_presence_enabled(self):
        """
        When presence is on, the stub servlet will not register.
        """
        # Presence is on
        self.hs.config.use_presence = True

        # Listen with the config
        self.hs._listen_http(self.hs.config.worker.worker_listeners[0])

        # Grab the resource from the site that was told to listen
        self.assertEqual(len(self.reactor.tcpServers), 1)
        site = self.reactor.tcpServers[0][1]
        self.resource = site.resource.children[b"_matrix"].children[b"client"]

        request, channel = self.make_request("PUT", "presence/a/status")
        self.render(request)

        # 400 + unrecognised, because nothing is registered
        self.assertEqual(channel.code, 400)
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")

    def test_listen_http_with_presence_disabled(self):
        """
        When presence is off, the stub servlet will register.
        """
        # Presence is off
        self.hs.config.use_presence = False

        # Listen with the config
        self.hs._listen_http(self.hs.config.worker.worker_listeners[0])

        # Grab the resource from the site that was told to listen
        self.assertEqual(len(self.reactor.tcpServers), 1)
        site = self.reactor.tcpServers[0][1]
        self.resource = site.resource.children[b"_matrix"].children[b"client"]

        request, channel = self.make_request("PUT", "presence/a/status")
        self.render(request)

        # 401, because the stub servlet still checks authentication
        self.assertEqual(channel.code, 401)
        self.assertEqual(channel.json_body["errcode"], "M_MISSING_TOKEN")
