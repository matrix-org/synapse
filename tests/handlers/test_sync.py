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
from typing import Optional
from unittest.mock import MagicMock, Mock, patch

from synapse.api.constants import EventTypes, JoinRules
from synapse.api.errors import Codes, ResourceLimitError
from synapse.api.filtering import Filtering
from synapse.api.room_versions import RoomVersions
from synapse.handlers.sync import SyncConfig, SyncResult
from synapse.rest import admin
from synapse.rest.client import knock, login, room
from synapse.server import HomeServer
from synapse.types import UserID, create_requester

import tests.unittest
import tests.utils
from tests.test_utils import make_awaitable


class SyncTestCase(tests.unittest.HomeserverTestCase):
    """Tests Sync Handler."""

    servlets = [
        admin.register_servlets,
        knock.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: HomeServer):
        self.sync_handler = self.hs.get_sync_handler()
        self.store = self.hs.get_datastores().main

        # AuthBlocking reads from the hs' config on initialization. We need to
        # modify its config instead of the hs'
        self.auth_blocking = self.hs.get_auth_blocking()

    def test_wait_for_sync_for_user_auth_blocking(self):
        user_id1 = "@user1:test"
        user_id2 = "@user2:test"
        sync_config = generate_sync_config(user_id1)
        requester = create_requester(user_id1)

        self.reactor.advance(100)  # So we get not 0 time
        self.auth_blocking._limit_usage_by_mau = True
        self.auth_blocking._max_mau_value = 1

        # Check that the happy case does not throw errors
        self.get_success(self.store.upsert_monthly_active_user(user_id1))
        self.get_success(
            self.sync_handler.wait_for_sync_for_user(requester, sync_config)
        )

        # Test that global lock works
        self.auth_blocking._hs_disabled = True
        e = self.get_failure(
            self.sync_handler.wait_for_sync_for_user(requester, sync_config),
            ResourceLimitError,
        )
        self.assertEqual(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

        self.auth_blocking._hs_disabled = False

        sync_config = generate_sync_config(user_id2)
        requester = create_requester(user_id2)

        e = self.get_failure(
            self.sync_handler.wait_for_sync_for_user(requester, sync_config),
            ResourceLimitError,
        )
        self.assertEqual(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

    def test_unknown_room_version(self):
        """
        A room with an unknown room version should not break sync (and should be excluded).
        """
        inviter = self.register_user("creator", "pass", admin=True)
        inviter_tok = self.login("@creator:test", "pass")

        user = self.register_user("user", "pass")
        tok = self.login("user", "pass")

        # Do an initial sync on a different device.
        requester = create_requester(user)
        initial_result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester, sync_config=generate_sync_config(user, device_id="dev")
            )
        )

        # Create a room as the user.
        joined_room = self.helper.create_room_as(user, tok=tok)

        # Invite the user to the room as someone else.
        invite_room = self.helper.create_room_as(inviter, tok=inviter_tok)
        self.helper.invite(invite_room, targ=user, tok=inviter_tok)

        knock_room = self.helper.create_room_as(
            inviter, room_version=RoomVersions.V7.identifier, tok=inviter_tok
        )
        self.helper.send_state(
            knock_room,
            EventTypes.JoinRules,
            {"join_rule": JoinRules.KNOCK},
            tok=inviter_tok,
        )
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/knock/%s" % (knock_room,),
            b"{}",
            tok,
        )
        self.assertEqual(200, channel.code, channel.result)

        # The rooms should appear in the sync response.
        result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester, sync_config=generate_sync_config(user)
            )
        )
        self.assertIn(joined_room, [r.room_id for r in result.joined])
        self.assertIn(invite_room, [r.room_id for r in result.invited])
        self.assertIn(knock_room, [r.room_id for r in result.knocked])

        # Test a incremental sync (by providing a since_token).
        result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester,
                sync_config=generate_sync_config(user, device_id="dev"),
                since_token=initial_result.next_batch,
            )
        )
        self.assertIn(joined_room, [r.room_id for r in result.joined])
        self.assertIn(invite_room, [r.room_id for r in result.invited])
        self.assertIn(knock_room, [r.room_id for r in result.knocked])

        # Poke the database and update the room version to an unknown one.
        for room_id in (joined_room, invite_room, knock_room):
            self.get_success(
                self.hs.get_datastores().main.db_pool.simple_update(
                    "rooms",
                    keyvalues={"room_id": room_id},
                    updatevalues={"room_version": "unknown-room-version"},
                    desc="updated-room-version",
                )
            )

        # Blow away caches (supported room versions can only change due to a restart).
        self.store.get_rooms_for_user_with_stream_ordering.invalidate_all()
        self.store.get_rooms_for_user.invalidate_all()
        self.get_success(self.store._get_event_cache.clear())
        self.store._event_ref.clear()

        # The rooms should be excluded from the sync response.
        # Get a new request key.
        result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester, sync_config=generate_sync_config(user)
            )
        )
        self.assertNotIn(joined_room, [r.room_id for r in result.joined])
        self.assertNotIn(invite_room, [r.room_id for r in result.invited])
        self.assertNotIn(knock_room, [r.room_id for r in result.knocked])

        # The rooms should also not be in an incremental sync.
        result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester,
                sync_config=generate_sync_config(user, device_id="dev"),
                since_token=initial_result.next_batch,
            )
        )
        self.assertNotIn(joined_room, [r.room_id for r in result.joined])
        self.assertNotIn(invite_room, [r.room_id for r in result.invited])
        self.assertNotIn(knock_room, [r.room_id for r in result.knocked])

    def test_ban_wins_race_with_join(self):
        """Rooms shouldn't appear under "joined" if a join loses a race to a ban.

        A complicated edge case. Imagine the following scenario:

        * you attempt to join a room
        * racing with that is a ban which comes in over federation, which ends up with
          an earlier stream_ordering than the join.
        * you get a sync response with a sync token which is _after_ the ban, but before
          the join
        * now your join lands; it is a valid event because its `prev_event`s predate the
          ban, but will not make it into current_state_events (because bans win over
          joins in state res, essentially).
        * When we do a sync from the incremental sync, the only event in the timeline
          is your join ... and yet you aren't joined.

        The ban coming in over federation isn't crucial for this behaviour; the key
        requirements are:
        1. the homeserver generates a join event with prev_events that precede the ban
           (so that it passes the "are you banned" test)
        2. the join event has a stream_ordering after that of the ban.

        We use monkeypatching to artificially trigger condition (1).
        """
        # A local user Alice creates a room.
        owner = self.register_user("alice", "password")
        owner_tok = self.login(owner, "password")
        room_id = self.helper.create_room_as(owner, is_public=True, tok=owner_tok)

        # Do a sync as Alice to get the latest event in the room.
        alice_sync_result: SyncResult = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                create_requester(owner), generate_sync_config(owner)
            )
        )
        self.assertEqual(len(alice_sync_result.joined), 1)
        self.assertEqual(alice_sync_result.joined[0].room_id, room_id)
        last_room_creation_event_id = (
            alice_sync_result.joined[0].timeline.events[-1].event_id
        )

        # Eve, a ne'er-do-well, registers.
        eve = self.register_user("eve", "password")
        eve_token = self.login(eve, "password")

        # Alice preemptively bans Eve.
        self.helper.ban(room_id, owner, eve, tok=owner_tok)

        # Eve syncs.
        eve_requester = create_requester(eve)
        eve_sync_config = generate_sync_config(eve)
        eve_sync_after_ban: SyncResult = self.get_success(
            self.sync_handler.wait_for_sync_for_user(eve_requester, eve_sync_config)
        )

        # Sanity check this sync result. We shouldn't be joined to the room.
        self.assertEqual(eve_sync_after_ban.joined, [])

        # Eve tries to join the room. We monkey patch the internal logic which selects
        # the prev_events used when creating the join event, such that the ban does not
        # precede the join.
        mocked_get_prev_events = patch.object(
            self.hs.get_datastores().main,
            "get_prev_events_for_room",
            new_callable=MagicMock,
            return_value=make_awaitable([last_room_creation_event_id]),
        )
        with mocked_get_prev_events:
            self.helper.join(room_id, eve, tok=eve_token)

        # Eve makes a second, incremental sync.
        eve_incremental_sync_after_join: SyncResult = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                eve_requester,
                eve_sync_config,
                since_token=eve_sync_after_ban.next_batch,
            )
        )
        # Eve should not see herself as joined to the room.
        self.assertEqual(eve_incremental_sync_after_join.joined, [])

        # If we did a third initial sync, we should _still_ see eve is not joined to the room.
        eve_initial_sync_after_join: SyncResult = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                eve_requester,
                eve_sync_config,
                since_token=None,
            )
        )
        self.assertEqual(eve_initial_sync_after_join.joined, [])


_request_key = 0


def generate_sync_config(
    user_id: str, device_id: Optional[str] = "device_id"
) -> SyncConfig:
    """Generate a sync config (with a unique request key)."""
    global _request_key
    _request_key += 1
    return SyncConfig(
        user=UserID.from_string(user_id),
        filter_collection=Filtering(Mock()).DEFAULT_FILTER_COLLECTION,
        is_guest=False,
        request_key=("request_key", _request_key),
        device_id=device_id,
    )
