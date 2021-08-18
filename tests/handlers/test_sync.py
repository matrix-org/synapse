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

from synapse.api.errors import Codes, ResourceLimitError
from synapse.api.filtering import DEFAULT_FILTER_COLLECTION
from synapse.handlers.sync import SyncConfig
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import UserID, create_requester

import tests.unittest
import tests.utils


class SyncTestCase(tests.unittest.HomeserverTestCase):
    """Tests Sync Handler."""

    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: HomeServer):
        self.sync_handler = self.hs.get_sync_handler()
        self.store = self.hs.get_datastore()

        # AuthBlocking reads from the hs' config on initialization. We need to
        # modify its config instead of the hs'
        self.auth_blocking = self.hs.get_auth()._auth_blocking

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
        self.assertEquals(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

        self.auth_blocking._hs_disabled = False

        sync_config = generate_sync_config(user_id2)
        requester = create_requester(user_id2)

        e = self.get_failure(
            self.sync_handler.wait_for_sync_for_user(requester, sync_config),
            ResourceLimitError,
        )
        self.assertEquals(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

    def test_unknown_room_version(self):
        """
        A room with an unknown room version should not break sync (and should be excluded).
        """
        inviter = self.register_user("creator", "pass", admin=True)
        inviter_tok = self.login("@creator:test", "pass")

        user = self.register_user("user", "pass")
        tok = self.login("user", "pass")

        # Create a room as the user.
        joined_room = self.helper.create_room_as(user, tok=tok)

        # Invite the user to the room as someone else.
        invite_room = self.helper.create_room_as(inviter, tok=inviter_tok)
        self.helper.invite(invite_room, targ=user, tok=inviter_tok)

        # The rooms should appear in the sync response.
        requester = create_requester(user)
        result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester, sync_config=generate_sync_config(user)
            )
        )
        self.assertIn(joined_room, [r.room_id for r in result.joined])
        self.assertIn(invite_room, [r.room_id for r in result.invited])

        # Poke the database and update the room version to an unknown one.
        for room_id in (joined_room, invite_room):
            self.get_success(
                self.hs.get_datastores().main.db_pool.simple_update(
                    "rooms",
                    keyvalues={"room_id": room_id},
                    updatevalues={"room_version": "unknown-room-version"},
                    desc="updated-room-version",
                )
            )

        # Blow away the cache.
        self.get_success(
            self.store.get_rooms_for_user_with_stream_ordering.invalidate_all()
        )

        # The rooms should be excluded from the sync response.
        # Get a new request key.
        result = self.get_success(
            self.sync_handler.wait_for_sync_for_user(
                requester, sync_config=generate_sync_config(user)
            )
        )
        self.assertNotIn(joined_room, [r.room_id for r in result.joined])
        self.assertNotIn(invite_room, [r.room_id for r in result.invited])

        # TODO Test a partial sync (by providing a since_token).


_request_key = 0


def generate_sync_config(user_id: str) -> SyncConfig:
    """Generate a sync config (with a unique request key)."""
    global _request_key
    _request_key += 1
    return SyncConfig(
        user=UserID.from_string(user_id),
        filter_collection=DEFAULT_FILTER_COLLECTION,
        is_guest=False,
        request_key=("request_key", _request_key),
        device_id="device_id",
    )
