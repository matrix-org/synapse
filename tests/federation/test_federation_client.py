# Copyright 2022 Matrix.org Federation C.I.C
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
from unittest import mock

import twisted.web.client
from twisted.internet import defer
from twisted.internet.protocol import Protocol
from twisted.python.failure import Failure
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.room_versions import RoomVersions
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests.unittest import FederatingHomeserverTestCase


class FederationClientTest(FederatingHomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer):
        super().prepare(reactor, clock, homeserver)

        # mock out the Agent used by the federation client, which is easier than
        # catching the HTTPS connection and do the TLS stuff.
        self._mock_agent = mock.create_autospec(twisted.web.client.Agent, spec_set=True)
        homeserver.get_federation_http_client().agent = self._mock_agent

    def test_get_room_state(self):
        creator = f"@creator:{self.OTHER_SERVER_NAME}"
        test_room_id = "!room_id"

        # mock up some events to use in the response.
        # In real life, these would have things in `prev_events` and `auth_events`, but that's
        # a bit annoying to mock up, and the code under test doesn't care, so we don't bother.
        create_event_dict = self.add_hashes_and_signatures(
            {
                "room_id": test_room_id,
                "type": "m.room.create",
                "state_key": "",
                "sender": creator,
                "content": {"creator": creator},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 500,
            }
        )
        member_event_dict = self.add_hashes_and_signatures(
            {
                "room_id": test_room_id,
                "type": "m.room.member",
                "sender": creator,
                "state_key": creator,
                "content": {"membership": "join"},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 600,
            }
        )
        pl_event_dict = self.add_hashes_and_signatures(
            {
                "room_id": test_room_id,
                "type": "m.room.power_levels",
                "sender": creator,
                "state_key": "",
                "content": {},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 700,
            }
        )

        # mock up the response, and have the agent return it
        self._mock_agent.request.side_effect = lambda *args, **kwargs: defer.succeed(
            _mock_response(
                {
                    "pdus": [
                        create_event_dict,
                        member_event_dict,
                        pl_event_dict,
                    ],
                    "auth_chain": [
                        create_event_dict,
                        member_event_dict,
                    ],
                }
            )
        )

        # now fire off the request
        state_resp, auth_resp = self.get_success(
            self.hs.get_federation_client().get_room_state(
                "yet_another_server",
                test_room_id,
                "event_id",
                RoomVersions.V9,
            )
        )

        # check the right call got made to the agent
        self._mock_agent.request.assert_called_once_with(
            b"GET",
            b"matrix://yet_another_server/_matrix/federation/v1/state/%21room_id?event_id=event_id",
            headers=mock.ANY,
            bodyProducer=None,
        )

        # ... and that the response is correct.

        # the auth_resp should be empty because all the events are also in state
        self.assertEqual(auth_resp, [])

        # all of the events should be returned in state_resp, though not necessarily
        # in the same order. We just check the type on the assumption that if the type
        # is right, so is the rest of the event.
        self.assertCountEqual(
            [e.type for e in state_resp],
            ["m.room.create", "m.room.member", "m.room.power_levels"],
        )


def _mock_response(resp: JsonDict):
    body = json.dumps(resp).encode("utf-8")

    def deliver_body(p: Protocol):
        p.dataReceived(body)
        p.connectionLost(Failure(twisted.web.client.ResponseDone()))

    response = mock.Mock(
        code=200,
        phrase=b"OK",
        headers=twisted.web.client.Headers({"content-Type": ["application/json"]}),
        length=len(body),
        deliverBody=deliver_body,
    )
    mock.seal(response)
    return response
