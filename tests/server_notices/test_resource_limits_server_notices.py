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

from synapse.api.constants import EventTypes, ServerNoticeMsgType
from synapse.api.errors import ResourceLimitError
from synapse.server_notices.resource_limits_server_notices import (
    ResourceLimitsServerNotices,
)

from tests import unittest


class TestResourceLimitsServerNotices(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs_config = self.default_config("test")
        hs_config["server_notices"] = {
            "system_mxid_localpart": "server",
            "system_mxid_display_name": "test display name",
            "system_mxid_avatar_url": None,
            "room_name": "Server Notices",
        }

        hs = self.setup_test_homeserver(config=hs_config, expire_access_token=True)
        return hs

    def prepare(self, reactor, clock, hs):
        self.server_notices_sender = self.hs.get_server_notices_sender()

        # relying on [1] is far from ideal, but the only case where
        # ResourceLimitsServerNotices class needs to be isolated is this test,
        # general code should never have a reason to do so ...
        self._rlsn = self.server_notices_sender._server_notices[1]
        if not isinstance(self._rlsn, ResourceLimitsServerNotices):
            raise Exception("Failed to find reference to ResourceLimitsServerNotices")

        self._rlsn._store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(1000)
        )
        self._send_notice = self._rlsn._server_notices_manager.send_notice
        self._rlsn._server_notices_manager.send_notice = Mock()
        self._rlsn._state.get_current_state = Mock(return_value=defer.succeed(None))
        self._rlsn._store.get_events = Mock(return_value=defer.succeed({}))

        self._send_notice = self._rlsn._server_notices_manager.send_notice

        self.hs.config.limit_usage_by_mau = True
        self.user_id = "@user_id:test"

        # self.server_notices_mxid = "@server:test"
        # self.server_notices_mxid_display_name = None
        # self.server_notices_mxid_avatar_url = None
        # self.server_notices_room_name = "Server Notices"

        self._rlsn._server_notices_manager.get_notice_room_for_user = Mock(
            returnValue=""
        )
        self._rlsn._store.add_tag_to_room = Mock()
        self._rlsn._store.get_tags_for_room = Mock(return_value={})
        self.hs.config.admin_contact = "mailto:user@test.com"

    def test_maybe_send_server_notice_to_user_flag_off(self):
        """Tests cases where the flags indicate nothing to do"""
        # test hs disabled case
        self.hs.config.hs_disabled = True

        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()
        # Test when mau limiting disabled
        self.hs.config.hs_disabled = False
        self.hs.config.limit_usage_by_mau = False
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()

    def test_maybe_send_server_notice_to_user_remove_blocked_notice(self):
        """Test when user has blocked notice, but should have it removed"""

        self._rlsn._auth.check_auth_blocking = Mock()
        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=defer.succeed({"123": mock_event})
        )

        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        # Would be better to check the content, but once == remove blocking event
        self._send_notice.assert_called_once()

    def test_maybe_send_server_notice_to_user_remove_blocked_notice_noop(self):
        """
        Test when user has blocked notice, but notice ought to be there (NOOP)
        """
        self._rlsn._auth.check_auth_blocking = Mock(
            side_effect=ResourceLimitError(403, "foo")
        )

        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=defer.succeed({"123": mock_event})
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()

    def test_maybe_send_server_notice_to_user_add_blocked_notice(self):
        """
        Test when user does not have blocked notice, but should have one
        """

        self._rlsn._auth.check_auth_blocking = Mock(
            side_effect=ResourceLimitError(403, "foo")
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        # Would be better to check contents, but 2 calls == set blocking event
        self.assertTrue(self._send_notice.call_count == 2)

    def test_maybe_send_server_notice_to_user_add_blocked_notice_noop(self):
        """
        Test when user does not have blocked notice, nor should they (NOOP)
        """
        self._rlsn._auth.check_auth_blocking = Mock()

        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()

    def test_maybe_send_server_notice_to_user_not_in_mau_cohort(self):
        """
        Test when user is not part of the MAU cohort - this should not ever
        happen - but ...
        """
        self._rlsn._auth.check_auth_blocking = Mock()
        self._rlsn._store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(None)
        )
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        self._send_notice.assert_not_called()


class TestResourceLimitsServerNoticesWithRealRooms(unittest.HomeserverTestCase):
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

        self.hs.config.limit_usage_by_mau = True
        self.hs.config.hs_disabled = False
        self.hs.config.max_mau_value = 5
        self.hs.config.server_notices_mxid = "@server:test"
        self.hs.config.server_notices_mxid_display_name = None
        self.hs.config.server_notices_mxid_avatar_url = None
        self.hs.config.server_notices_room_name = "Test Server Notice Room"

        self.user_id = "@user_id:test"

        self.hs.config.admin_contact = "mailto:user@test.com"

    def test_server_notice_only_sent_once(self):
        self.store.get_monthly_active_count = Mock(return_value=1000)

        self.store.user_last_seen_monthly_active = Mock(return_value=1000)

        # Call the function multiple times to ensure we only send the notice once
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))
        self.get_success(self._rlsn.maybe_send_server_notice_to_user(self.user_id))

        # Now lets get the last load of messages in the service notice room and
        # check that there is only one server notice
        room_id = self.get_success(
            self.server_notices_manager.get_notice_room_for_user(self.user_id)
        )

        token = self.get_success(self.event_source.get_current_token())
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
