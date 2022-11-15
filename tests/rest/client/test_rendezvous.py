# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest.client import rendezvous
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config

endpoint = "/_matrix/client/unstable/org.matrix.msc3886/rendezvous"


class RendezvousServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        rendezvous.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.hs = self.setup_test_homeserver()
        return self.hs

    def test_disabled(self) -> None:
        channel = self.make_request("POST", endpoint, {}, access_token=None)
        self.assertEqual(channel.code, 400)

    @override_config({"experimental_features": {"msc3886_endpoint": "/asd"}})
    def test_redirect(self) -> None:
        channel = self.make_request("POST", endpoint, {}, access_token=None)
        self.assertEqual(channel.code, 307)
        self.assertEqual(channel.headers.getRawHeaders("Location"), ["/asd"])
