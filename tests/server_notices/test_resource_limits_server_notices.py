# -*- coding: utf-8 -*-
# Copyright 2018, 2019 New Vector Ltd
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

from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, LimitBlockingTypes, ServerNoticeMsgType
from synapse.api.errors import ResourceLimitError
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import sync
from synapse.server_notices.resource_limits_server_notices import (
    ResourceLimitsServerNotices,
)

from tests import unittest
from tests.test_utils import make_awaitable
from tests.unittest import override_config
from tests.utils import default_config


class TestResourceLimitsServerNotices(unittest.HomeserverTestCase):
    def default_config(self):
        config = default_config("test")

        config.update(
            {
                "admin_contact": "mailto:user@test.com",
                "limit_usage_by_mau": True,
                "server_notices": {
                    "system_mxid_localpart": "server",
                    "system_mxid_display_name": "test display name",
                    "system_mxid_avatar_url": None,
                    "room_name": "Server Notices",
                },
            }
        )

        # apply any additional config which was specified via the override_config
        # decorator.
        if self._extra_config is not None:
            config.update(self._extra_config)

        return config

    def prepare(self, reactor, clock, hs):
        self.server_notices_sender = self.hs.get_server_notices_sender()

        # relying on [1] is far from ideal, but the only case where
        # ResourceLimitsServerNotices class needs to be isolated is this test,
        # general code should never have a reason to do so ...
        self._rlsn = self.server_notices_sender._server_notices[1]
        if not isinstance(self._rlsn, ResourceLimitsServerNotices):
            raise Exception("Failed to find reference to ResourceLimitsServerNotices")

        self._rlsn._store.user_last_seen_monthly_active = Mock(
            return_value=make_awaitable(1000)
        )
        self._rlsn._server_notices_manager.send_notice = Mock(
            return_value=defer.succeed(Mock())
        )
        self._send_notice = self._rlsn._server_notices_manager.send_notice

        self.user_id = "@user_id:test"

        self._rlsn._server_notices_manager.get_or_create_notice_room_for_user = Mock(
            return_value=defer.succeed("!something:localhost")
        )
        self._rlsn._store.add_tag_to_room = Mock(return_value=defer.succeed(None))
        self._rlsn._store.get_tags_for_room = Mock(return_value=make_awaitable({}))

    @override_config({"hs_disabled": True})
    def test_maybe_send_server_notice_disabled_hs(self):
        """If the HS is disabled, we should not send notices"""
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        self._send_notice.assert_not_called()

    @override_config({"limit_usage_by_mau": False})
    def test_maybe_send_server_notice_to_user_flag_off(self):
        """If mau limiting is disabled, we should not send notices"""
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        self._send_notice.assert_not_called()

    def test_maybe_send_server_notice_to_user_remove_blocked_notice(self):
        """Test when user has blocked notice, but should have it removed"""

        self._rlsn._auth.check_auth_blocking = Mock(return_value=defer.succeed(None))
        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=make_awaitable({"123": mock_event})
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        # Would be better to check the content, but once == remove blocking event
        self._send_notice.assert_called_once()

    def test_maybe_send_server_notice_to_user_remove_blocked_notice_noop(self):
        """
        Test when user has blocked notice, but notice ought to be there (NOOP)
        """
        self._rlsn._auth.check_auth_blocking = Mock(
            return_value=defer.succeed(None), side_effect=ResourceLimitError(403, "foo")
        )

        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=make_awaitable({"123": mock_event})
        )

        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()

    def test_maybe_send_server_notice_to_user_add_blocked_notice(self):
        """
        Test when user does not have blocked notice, but should have one
        """
        self._rlsn._auth.check_auth_blocking = Mock(
            return_value=defer.succeed(None), side_effect=ResourceLimitError(403, "foo")
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        # Would be better to check contents, but 2 calls == set blocking event
        self.assertEqual(self._send_notice.call_count, 2)

    def test_maybe_send_server_notice_to_user_add_blocked_notice_noop(self):
        """
        Test when user does not have blocked notice, nor should they (NOOP)
        """
        self._rlsn._auth.check_auth_blocking = Mock(return_value=defer.succeed(None))

        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()

    def test_maybe_send_server_notice_to_user_not_in_mau_cohort(self):
        """
        Test when user is not part of the MAU cohort - this should not ever
        happen - but ...
        """
        self._rlsn._auth.check_auth_blocking = Mock(return_value=defer.succeed(None))
        self._rlsn._store.user_last_seen_monthly_active = Mock(
            return_value=make_awaitable(None)
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()

    @override_config({"mau_limit_alerting": False})
    def test_maybe_send_server_notice_when_alerting_suppressed_room_unblocked(self):
        """
        Test that when server is over MAU limit and alerting is suppressed, then
        an alert message is not sent into the room
        """
        self._rlsn._auth.check_auth_blocking = Mock(
            return_value=defer.succeed(None),
            side_effect=ResourceLimitError(
                403, "foo", limit_type=LimitBlockingTypes.MONTHLY_ACTIVE_USER
            ),
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self.assertEqual(self._send_notice.call_count, 0)

    @override_config({"mau_limit_alerting": False})
    def test_check_hs_disabled_unaffected_by_mau_alert_suppression(self):
        """
        Test that when a server is disabled, that MAU limit alerting is ignored.
        """
        self._rlsn._auth.check_auth_blocking = Mock(
            return_value=defer.succeed(None),
            side_effect=ResourceLimitError(
                403, "foo", limit_type=LimitBlockingTypes.HS_DISABLED
            ),
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        # Would be better to check contents, but 2 calls == set blocking event
        self.assertEqual(self._send_notice.call_count, 2)

    @override_config({"mau_limit_alerting": False})
    def test_maybe_send_server_notice_when_alerting_suppressed_room_blocked(self):
        """
        When the room is already in a blocked state, test that when alerting
        is suppressed that the room is returned to an unblocked state.
        """
        self._rlsn._auth.check_auth_blocking = Mock(
            return_value=defer.succeed(None),
            side_effect=ResourceLimitError(
                403, "foo", limit_type=LimitBlockingTypes.MONTHLY_ACTIVE_USER
            ),
        )

        self._rlsn._server_notices_manager.__is_room_currently_blocked = Mock(
            return_value=defer.succeed((True, []))
        )

        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=make_awaitable({"123": mock_event})
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_called_once()


class TestResourceLimitsServerNoticesWithRealRooms(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        sync.register_servlets,
    ]

    def default_config(self):
        c = super().default_config()
        c["server_notices"] = {
            "system_mxid_localpart": "server",
            "system_mxid_display_name": None,
            "system_mxid_avatar_url": None,
            "room_name": "Test Server Notice Room",
        }
        c["limit_usage_by_mau"] = True
        c["max_mau_value"] = 5
        c["admin_contact"] = "mailto:user@test.com"
        return c

    def prepare(self, reactor, clock, hs):
        self.store = self.hs.get_datastore()
        self.server_notices_sender = self.hs.get_server_notices_sender()
        self.server_notices_manager = self.hs.get_server_notices_manager()
        self.event_source = self.hs.get_event_sources()

        # relying on [1] is far from ideal, but the only case where
        # ResourceLimitsServerNotices class needs to be isolated is this test,
        # general code should never have a reason to do so ...
        self._rlsn = self.server_notices_sender._server_notices[1]
        if not isinstance(self._rlsn, ResourceLimitsServerNotices):
            raise Exception("Failed to find reference to ResourceLimitsServerNotices")

        self.user_id = "@user_id:test"

    def test_server_notice_only_sent_once(self):
        self.store.get_monthly_active_count = Mock(return_value=make_awaitable(1000))

        self.store.user_last_seen_monthly_active = Mock(
            return_value=make_awaitable(1000)
        )

        # Call the function multiple times to ensure we only send the notice once
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        # Now lets get the last load of messages in the service notice room and
        # check that there is only one server notice
        room_id = self.get_success(
            self.server_notices_manager.get_or_create_notice_room_for_user(self.user_id)
        )

        token = self.event_source.get_current_token()
        events, _ = self.get_success(
            self.store.get_recent_events_for_room(
                room_id, limit=100, end_token=token.room_key
            )
        )

        count = 0
        for event in events:
            if event.type != EventTypes.Message:
                continue
            if event.content.get("msgtype") != ServerNoticeMsgType:
                continue

            count += 1

        self.assertEqual(count, 1)

    def test_no_invite_without_notice(self):
        """Tests that a user doesn't get invited to a server notices room without a
        server notice being sent.

        The scenario for this test is a single user on a server where the MAU limit
        hasn't been reached (since it's the only user and the limit is 5), so users
        shouldn't receive a server notice.
        """
        self.register_user("user", "password")
        tok = self.login("user", "password")

        channel = self.make_request("GET", "/sync?timeout=0", access_token=tok)

        invites = channel.json_body["rooms"]["invite"]
        self.assertEqual(len(invites), 0, invites)

    def test_invite_with_notice(self):
        """Tests that, if the MAU limit is hit, the server notices user invites each user
        to a room in which it has sent a notice.
        """
        user_id, tok, room_id = self._trigger_notice_and_join()

        # Sync again to retrieve the events in the room, so we can check whether this
        # room has a notice in it.
        channel = self.make_request("GET", "/sync?timeout=0", access_token=tok)

        # Scan the events in the room to search for a message from the server notices
        # user.
        events = channel.json_body["rooms"]["join"][room_id]["timeline"]["events"]
        notice_in_room = False
        for event in events:
            if (
                event["type"] == EventTypes.Message
                and event["sender"] == self.hs.config.server_notices_mxid
            ):
                notice_in_room = True

        self.assertTrue(notice_in_room, "No server notice in room")

    def _trigger_notice_and_join(self):
        """Creates enough active users to hit the MAU limit and trigger a system notice
        about it, then joins the system notices room with one of the users created.

        Returns:
            user_id (str): The ID of the user that joined the room.
            tok (str): The access token of the user that joined the room.
            room_id (str): The ID of the room that's been joined.
        """
        user_id = None
        tok = None
        invites = []

        # Register as many users as the MAU limit allows.
        for i in range(self.hs.config.max_mau_value):
            localpart = "user%d" % i
            user_id = self.register_user(localpart, "password")
            tok = self.login(localpart, "password")

            # Sync with the user's token to mark the user as active.
            channel = self.make_request(
                "GET",
                "/sync?timeout=0",
                access_token=tok,
            )

            # Also retrieves the list of invites for this user. We don't care about that
            # one except if we're processing the last user, which should have received an
            # invite to a room with a server notice about the MAU limit being reached.
            # We could also pick another user and sync with it, which would return an
            # invite to a system notices room, but it doesn't matter which user we're
            # using so we use the last one because it saves us an extra sync.
            invites = channel.json_body["rooms"]["invite"]

        # Make sure we have an invite to process.
        self.assertEqual(len(invites), 1, invites)

        # Join the room.
        room_id = list(invites.keys())[0]
        self.helper.join(room=room_id, user=user_id, tok=tok)

        return user_id, tok, room_id
