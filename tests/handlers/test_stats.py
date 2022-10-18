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

from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.storage.databases.main import stats

from tests import unittest

# The expected number of state events in a fresh public room.
EXPT_NUM_STATE_EVTS_IN_FRESH_PUBLIC_ROOM = 5
# The expected number of state events in a fresh private room.
EXPT_NUM_STATE_EVTS_IN_FRESH_PRIVATE_ROOM = 6


class StatsRoomTests(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastores().main
        self.handler = self.hs.get_stats_handler()

    def _add_background_updates(self):
        """
        Add the background updates we need to run.
        """
        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_process_rooms",
                    "progress_json": "{}",
                },
            )
        )
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_process_users",
                    "progress_json": "{}",
                    "depends_on": "populate_stats_process_rooms",
                },
            )
        )

    async def get_all_room_state(self):
        return await self.store.db_pool.simple_select_list(
            "room_stats_state", None, retcols=("name", "topic", "canonical_alias")
        )

    def _get_current_stats(self, stats_type, stat_id):
        table, id_col = stats.TYPE_TO_TABLE[stats_type]

        cols = list(stats.ABSOLUTE_STATS_FIELDS[stats_type])

        return self.get_success(
            self.store.db_pool.simple_select_one(
                table + "_current",
                {id_col: stat_id},
                cols,
                allow_none=True,
            )
        )

    def _perform_background_initial_update(self):
        # Do the initial population of the stats via the background update
        self._add_background_updates()

        self.wait_for_background_updates()

    def test_initial_room(self):
        """
        The background updates will build the table from scratch.
        """
        r = self.get_success(self.get_all_room_state())
        self.assertEqual(len(r), 0)

        # Disable stats
        self.hs.config.stats.stats_enabled = False
        self.handler.stats_enabled = False

        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "foo"}, tok=u1_token
        )

        # Stats disabled, shouldn't have done anything
        r = self.get_success(self.get_all_room_state())
        self.assertEqual(len(r), 0)

        # Enable stats
        self.hs.config.stats.stats_enabled = True
        self.handler.stats_enabled = True

        # Do the initial population of the user directory via the background update
        self._add_background_updates()

        self.wait_for_background_updates()

        r = self.get_success(self.get_all_room_state())

        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["topic"], "foo")

    def test_create_user(self):
        """
        When we create a user, it should have statistics already ready.
        """

        u1 = self.register_user("u1", "pass")

        u1stats = self._get_current_stats("user", u1)

        self.assertIsNotNone(u1stats)

        # not in any rooms by default
        self.assertEqual(u1stats["joined_rooms"], 0)

    def test_create_room(self):
        """
        When we create a room, it should have statistics already ready.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)
        r1stats = self._get_current_stats("room", r1)
        r2 = self.helper.create_room_as(u1, tok=u1token, is_public=False)
        r2stats = self._get_current_stats("room", r2)

        self.assertIsNotNone(r1stats)
        self.assertIsNotNone(r2stats)

        self.assertEqual(
            r1stats["current_state_events"], EXPT_NUM_STATE_EVTS_IN_FRESH_PUBLIC_ROOM
        )
        self.assertEqual(
            r2stats["current_state_events"], EXPT_NUM_STATE_EVTS_IN_FRESH_PRIVATE_ROOM
        )

        self.assertEqual(r1stats["joined_members"], 1)
        self.assertEqual(r1stats["invited_members"], 0)
        self.assertEqual(r1stats["banned_members"], 0)

        self.assertEqual(r2stats["joined_members"], 1)
        self.assertEqual(r2stats["invited_members"], 0)
        self.assertEqual(r2stats["banned_members"], 0)

    def test_updating_profile_information_does_not_increase_joined_members_count(self):
        """
        Check that the joined_members count does not increase when a user changes their
        profile information (which is done by sending another join membership event into
        the room.
        """
        self._perform_background_initial_update()

        # Create a user and room
        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        # Get the current room stats
        r1stats_ante = self._get_current_stats("room", r1)

        # Send a profile update into the room
        new_profile = {"displayname": "bob"}
        self.helper.change_membership(
            r1, u1, u1, "join", extra_data=new_profile, tok=u1token
        )

        # Get the new room stats
        r1stats_post = self._get_current_stats("room", r1)

        # Ensure that the user count did not changed
        self.assertEqual(r1stats_post["joined_members"], r1stats_ante["joined_members"])
        self.assertEqual(
            r1stats_post["local_users_in_room"], r1stats_ante["local_users_in_room"]
        )

    def test_send_state_event_nonoverwriting(self):
        """
        When we send a non-overwriting state event, it increments current_state_events
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        self.helper.send_state(
            r1, "cat.hissing", {"value": True}, tok=u1token, state_key="tabby"
        )

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.send_state(
            r1, "cat.hissing", {"value": False}, tok=u1token, state_key="moggy"
        )

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            1,
        )

    def test_join_first_time(self):
        """
        When a user joins a room for the first time, current_state_events and
        joined_members should increase by exactly 1.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        u2 = self.register_user("u2", "pass")
        u2token = self.login("u2", "pass")

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.join(r1, u2, tok=u2token)

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            1,
        )
        self.assertEqual(
            r1stats_post["joined_members"] - r1stats_ante["joined_members"], 1
        )

    def test_join_after_leave(self):
        """
        When a user joins a room after being previously left,
        joined_members should increase by exactly 1.
        current_state_events should not increase.
        left_members should decrease by exactly 1.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        u2 = self.register_user("u2", "pass")
        u2token = self.login("u2", "pass")

        self.helper.join(r1, u2, tok=u2token)
        self.helper.leave(r1, u2, tok=u2token)

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.join(r1, u2, tok=u2token)

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            0,
        )
        self.assertEqual(
            r1stats_post["joined_members"] - r1stats_ante["joined_members"], +1
        )
        self.assertEqual(
            r1stats_post["left_members"] - r1stats_ante["left_members"], -1
        )

    def test_invited(self):
        """
        When a user invites another user, current_state_events and
        invited_members should increase by exactly 1.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        u2 = self.register_user("u2", "pass")

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.invite(r1, u1, u2, tok=u1token)

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            1,
        )
        self.assertEqual(
            r1stats_post["invited_members"] - r1stats_ante["invited_members"], +1
        )

    def test_join_after_invite(self):
        """
        When a user joins a room after being invited and
        joined_members should increase by exactly 1.
        current_state_events should not increase.
        invited_members should decrease by exactly 1.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        u2 = self.register_user("u2", "pass")
        u2token = self.login("u2", "pass")

        self.helper.invite(r1, u1, u2, tok=u1token)

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.join(r1, u2, tok=u2token)

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            0,
        )
        self.assertEqual(
            r1stats_post["joined_members"] - r1stats_ante["joined_members"], +1
        )
        self.assertEqual(
            r1stats_post["invited_members"] - r1stats_ante["invited_members"], -1
        )

    def test_left(self):
        """
        When a user leaves a room after joining and
        left_members should increase by exactly 1.
        current_state_events should not increase.
        joined_members should decrease by exactly 1.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        u2 = self.register_user("u2", "pass")
        u2token = self.login("u2", "pass")

        self.helper.join(r1, u2, tok=u2token)

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.leave(r1, u2, tok=u2token)

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            0,
        )
        self.assertEqual(
            r1stats_post["left_members"] - r1stats_ante["left_members"], +1
        )
        self.assertEqual(
            r1stats_post["joined_members"] - r1stats_ante["joined_members"], -1
        )

    def test_banned(self):
        """
        When a user is banned from a room after joining and
        left_members should increase by exactly 1.
        current_state_events should not increase.
        banned_members should decrease by exactly 1.
        """

        self._perform_background_initial_update()

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        u2 = self.register_user("u2", "pass")
        u2token = self.login("u2", "pass")

        self.helper.join(r1, u2, tok=u2token)

        r1stats_ante = self._get_current_stats("room", r1)

        self.helper.change_membership(r1, u1, u2, "ban", tok=u1token)

        r1stats_post = self._get_current_stats("room", r1)

        self.assertEqual(
            r1stats_post["current_state_events"] - r1stats_ante["current_state_events"],
            0,
        )
        self.assertEqual(
            r1stats_post["banned_members"] - r1stats_ante["banned_members"], +1
        )
        self.assertEqual(
            r1stats_post["joined_members"] - r1stats_ante["joined_members"], -1
        )

    def test_initial_background_update(self):
        """
        Test that statistics can be generated by the initial background update
        handler.

        This test also tests that stats rows are not created for new subjects
        when stats are disabled. However, it may be desirable to change this
        behaviour eventually to still keep current rows.
        """

        self.hs.config.stats.stats_enabled = False
        self.handler.stats_enabled = False

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token)

        # test that these subjects, which were created during a time of disabled
        # stats, do not have stats.
        self.assertIsNone(self._get_current_stats("room", r1))
        self.assertIsNone(self._get_current_stats("user", u1))

        self.hs.config.stats.stats_enabled = True
        self.handler.stats_enabled = True

        self._perform_background_initial_update()

        r1stats = self._get_current_stats("room", r1)
        u1stats = self._get_current_stats("user", u1)

        self.assertEqual(r1stats["joined_members"], 1)
        self.assertEqual(
            r1stats["current_state_events"], EXPT_NUM_STATE_EVTS_IN_FRESH_PUBLIC_ROOM
        )

        self.assertEqual(u1stats["joined_rooms"], 1)

    def test_incomplete_stats(self):
        """
        This tests that we track incomplete statistics.

        We first test that incomplete stats are incrementally generated,
        following the preparation of a background regen.

        We then test that these incomplete rows are completed by the background
        regen.
        """

        u1 = self.register_user("u1", "pass")
        u1token = self.login("u1", "pass")
        u2 = self.register_user("u2", "pass")
        u2token = self.login("u2", "pass")
        u3 = self.register_user("u3", "pass")
        r1 = self.helper.create_room_as(u1, tok=u1token, is_public=False)

        # preparation stage of the initial background update
        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        self.get_success(
            self.store.db_pool.simple_delete(
                "room_stats_current", {"1": 1}, "test_delete_stats"
            )
        )
        self.get_success(
            self.store.db_pool.simple_delete(
                "user_stats_current", {"1": 1}, "test_delete_stats"
            )
        )

        self.helper.invite(r1, u1, u2, tok=u1token)
        self.helper.join(r1, u2, tok=u2token)
        self.helper.invite(r1, u1, u3, tok=u1token)
        self.helper.send(r1, "thou shalt yield", tok=u1token)

        # now do the background updates

        self.store.db_pool.updates._all_done = False
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_process_rooms",
                    "progress_json": "{}",
                },
            )
        )
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "populate_stats_process_users",
                    "progress_json": "{}",
                    "depends_on": "populate_stats_process_rooms",
                },
            )
        )

        self.wait_for_background_updates()

        r1stats_complete = self._get_current_stats("room", r1)
        u1stats_complete = self._get_current_stats("user", u1)
        u2stats_complete = self._get_current_stats("user", u2)

        # now we make our assertions

        # check that _complete rows are complete and correct
        self.assertEqual(r1stats_complete["joined_members"], 2)
        self.assertEqual(r1stats_complete["invited_members"], 1)

        self.assertEqual(
            r1stats_complete["current_state_events"],
            2 + EXPT_NUM_STATE_EVTS_IN_FRESH_PRIVATE_ROOM,
        )

        self.assertEqual(u1stats_complete["joined_rooms"], 1)
        self.assertEqual(u2stats_complete["joined_rooms"], 1)
