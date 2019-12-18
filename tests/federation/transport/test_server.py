# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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


from twisted.internet import defer

from synapse.config.ratelimiting import FederationRateLimitConfig
from synapse.federation.transport import server
from synapse.util.ratelimitutils import FederationRateLimiter

from tests import unittest
from tests.unittest import override_config


class RoomDirectoryFederationTests(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        class Authenticator(object):
            def authenticate_request(self, request, content):
                return defer.succeed("otherserver.nottld")

        ratelimiter = FederationRateLimiter(clock, FederationRateLimitConfig())
        server.register_servlets(
            homeserver, self.resource, Authenticator(), ratelimiter
        )

    @override_config({"allow_public_rooms_over_federation": False})
    def test_blocked_public_room_list_over_federation(self):
        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/publicRooms"
        )
        self.render(request)
        self.assertEquals(403, channel.code)

    @override_config({"allow_public_rooms_over_federation": True})
    def test_open_public_room_list_over_federation(self):
        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/publicRooms"
        )
        self.render(request)
        self.assertEquals(200, channel.code)
