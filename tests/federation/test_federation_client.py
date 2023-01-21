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

from unittest import mock

import twisted.web.client
from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests.test_utils import FakeResponse, event_injection
from tests.unittest import FederatingHomeserverTestCase


class FederationClientTest(FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer):
        super().prepare(reactor, clock, homeserver)

        # mock out the Agent used by the federation client, which is easier than
        # catching the HTTPS connection and do the TLS stuff.
        self._mock_agent = mock.create_autospec(twisted.web.client.Agent, spec_set=True)
        homeserver.get_federation_http_client().agent = self._mock_agent

        # Move clock up to somewhat realistic time so the PDU destination retry
        # works (`now` needs to be larger than `0 + PDU_RETRY_TIME_MS`).
        self.reactor.advance(1000000000)

        self.creator = f"@creator:{self.OTHER_SERVER_NAME}"
        self.test_room_id = "!room_id"

    def test_get_room_state(self):
        # mock up some events to use in the response.
        # In real life, these would have things in `prev_events` and `auth_events`, but that's
        # a bit annoying to mock up, and the code under test doesn't care, so we don't bother.
        create_event_dict = self.add_hashes_and_signatures_from_other_server(
            {
                "room_id": self.test_room_id,
                "type": "m.room.create",
                "state_key": "",
                "sender": self.creator,
                "content": {"creator": self.creator},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 500,
            }
        )
        member_event_dict = self.add_hashes_and_signatures_from_other_server(
            {
                "room_id": self.test_room_id,
                "type": "m.room.member",
                "sender": self.creator,
                "state_key": self.creator,
                "content": {"membership": "join"},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 600,
            }
        )
        pl_event_dict = self.add_hashes_and_signatures_from_other_server(
            {
                "room_id": self.test_room_id,
                "type": "m.room.power_levels",
                "sender": self.creator,
                "state_key": "",
                "content": {},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 700,
            }
        )

        # mock up the response, and have the agent return it
        self._mock_agent.request.side_effect = lambda *args, **kwargs: defer.succeed(
            FakeResponse.json(
                payload={
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
                "yet.another.server",
                self.test_room_id,
                "event_id",
                RoomVersions.V9,
            )
        )

        # check the right call got made to the agent
        self._mock_agent.request.assert_called_once_with(
            b"GET",
            b"matrix://yet.another.server/_matrix/federation/v1/state/%21room_id?event_id=event_id",
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

    def test_get_pdu_returns_nothing_when_event_does_not_exist(self):
        """No event should be returned when the event does not exist"""
        pulled_pdu_info = self.get_success(
            self.hs.get_federation_client().get_pdu(
                ["yet.another.server"],
                "event_should_not_exist",
                RoomVersions.V9,
            )
        )
        self.assertEqual(pulled_pdu_info, None)

    def test_get_pdu(self):
        """Test to make sure an event is returned by `get_pdu()`"""
        self._get_pdu_once()

    def test_get_pdu_event_from_cache_is_pristine(self):
        """Test that modifications made to events returned by `get_pdu()`
        do not propagate back to to the internal cache (events returned should
        be a copy).
        """

        # Get the PDU in the cache
        remote_pdu = self._get_pdu_once()

        # Modify the the event reference.
        # This change should not make it back to the `_get_pdu_cache`.
        remote_pdu.internal_metadata.outlier = True

        # Get the event again. This time it should read it from cache.
        pulled_pdu_info2 = self.get_success(
            self.hs.get_federation_client().get_pdu(
                ["yet.another.server"],
                remote_pdu.event_id,
                RoomVersions.V9,
            )
        )
        self.assertIsNotNone(pulled_pdu_info2)
        remote_pdu2 = pulled_pdu_info2.pdu

        # Sanity check that we are working against the same event
        self.assertEqual(remote_pdu.event_id, remote_pdu2.event_id)

        # Make sure the event does not include modification from earlier
        self.assertIsNotNone(remote_pdu2)
        self.assertEqual(remote_pdu2.internal_metadata.outlier, False)

    def _get_pdu_once(self) -> EventBase:
        """Retrieve an event via `get_pdu()` and assert that an event was returned.
        Also used to prime the cache for subsequent test logic.
        """
        message_event_dict = self.add_hashes_and_signatures_from_other_server(
            {
                "room_id": self.test_room_id,
                "type": "m.room.message",
                "sender": self.creator,
                "state_key": "",
                "content": {},
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 700,
                "depth": 10,
            }
        )

        # mock up the response, and have the agent return it
        self._mock_agent.request.side_effect = lambda *args, **kwargs: defer.succeed(
            FakeResponse.json(
                payload={
                    "origin": "yet.another.server",
                    "origin_server_ts": 900,
                    "pdus": [
                        message_event_dict,
                    ],
                }
            )
        )

        pulled_pdu_info = self.get_success(
            self.hs.get_federation_client().get_pdu(
                ["yet.another.server"],
                "event_id",
                RoomVersions.V9,
            )
        )
        self.assertIsNotNone(pulled_pdu_info)
        remote_pdu = pulled_pdu_info.pdu

        # check the right call got made to the agent
        self._mock_agent.request.assert_called_once_with(
            b"GET",
            b"matrix://yet.another.server/_matrix/federation/v1/event/event_id",
            headers=mock.ANY,
            bodyProducer=None,
        )

        self.assertIsNotNone(remote_pdu)
        self.assertEqual(remote_pdu.internal_metadata.outlier, False)

        return remote_pdu

    def test_backfill_invalid_signature_records_failed_pull_attempts(
        self,
    ) -> None:
        """
        Test to make sure that events from /backfill with invalid signatures get
        recorded as failed pull attempts.
        """
        OTHER_USER = f"@user:{self.OTHER_SERVER_NAME}"
        main_store = self.hs.get_datastores().main

        # Create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)

        # We purposely don't run `add_hashes_and_signatures_from_other_server`
        # over this because we want the signature check to fail.
        pulled_event, _ = self.get_success(
            event_injection.create_event(
                self.hs,
                room_id=room_id,
                sender=OTHER_USER,
                type="test_event_type",
                content={"body": "garply"},
            )
        )

        # We expect an outbound request to /backfill, so stub that out
        self._mock_agent.request.side_effect = lambda *args, **kwargs: defer.succeed(
            FakeResponse.json(
                payload={
                    "origin": "yet.another.server",
                    "origin_server_ts": 900,
                    # Mimic the other server returning our new `pulled_event`
                    "pdus": [pulled_event.get_pdu_json()],
                }
            )
        )

        self.get_success(
            self.hs.get_federation_client().backfill(
                # We use "yet.another.server" instead of
                # `self.OTHER_SERVER_NAME` because we want to see the behavior
                # from `_check_sigs_and_hash_and_fetch_one` where it tries to
                # fetch the PDU again from the origin server if the signature
                # fails. Just want to make sure that the failure is counted from
                # both code paths.
                dest="yet.another.server",
                room_id=room_id,
                limit=1,
                extremities=[pulled_event.event_id],
            ),
        )

        # Make sure our failed pull attempt was recorded
        backfill_num_attempts = self.get_success(
            main_store.db_pool.simple_select_one_onecol(
                table="event_failed_pull_attempts",
                keyvalues={"event_id": pulled_event.event_id},
                retcol="num_attempts",
            )
        )
        # This is 2 because it failed once from `self.OTHER_SERVER_NAME` and the
        # other from "yet.another.server"
        self.assertEqual(backfill_num_attempts, 2)
