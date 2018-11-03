from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, ServerNoticeMsgType
from synapse.api.errors import ResourceLimitError
from synapse.handlers.auth import AuthHandler
from synapse.server_notices.resource_limits_server_notices import (
    ResourceLimitsServerNotices,
)

from tests import unittest
from tests.utils import setup_test_homeserver


class AuthHandlers(object):
    def __init__(self, hs):
        self.auth_handler = AuthHandler(hs)


class TestResourceLimitsServerNotices(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup, handlers=None)
        self.hs.handlers = AuthHandlers(self.hs)
        self.auth_handler = self.hs.handlers.auth_handler
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

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_flag_off(self):
        """Tests cases where the flags indicate nothing to do"""
        # test hs disabled case
        self.hs.config.hs_disabled = True

        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()
        # Test when mau limiting disabled
        self.hs.config.hs_disabled = False
        self.hs.limit_usage_by_mau = False
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_remove_blocked_notice(self):
        """Test when user has blocked notice, but should have it removed"""

        self._rlsn._auth.check_auth_blocking = Mock()
        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=defer.succeed({"123": mock_event})
        )

        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)
        # Would be better to check the content, but once == remove blocking event
        self._send_notice.assert_called_once()

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_remove_blocked_notice_noop(self):
        """Test when user has blocked notice, but notice ought to be there (NOOP)"""
        self._rlsn._auth.check_auth_blocking = Mock(
            side_effect=ResourceLimitError(403, 'foo')
        )

        mock_event = Mock(
            type=EventTypes.Message, content={"msgtype": ServerNoticeMsgType}
        )
        self._rlsn._store.get_events = Mock(
            return_value=defer.succeed({"123": mock_event})
        )
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_add_blocked_notice(self):
        """Test when user does not have blocked notice, but should have one"""

        self._rlsn._auth.check_auth_blocking = Mock(
            side_effect=ResourceLimitError(403, 'foo')
        )
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        # Would be better to check contents, but 2 calls == set blocking event
        self.assertTrue(self._send_notice.call_count == 2)

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_add_blocked_notice_noop(self):
        """Test when user does not have blocked notice, nor should they (NOOP)"""

        self._rlsn._auth.check_auth_blocking = Mock()

        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_not_in_mau_cohort(self):

        """Test when user is not part of the MAU cohort - this should not ever
        happen - but ...
        """

        self._rlsn._auth.check_auth_blocking = Mock()
        self._rlsn._store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(None)
        )
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()


class TestResourceLimitsServerNoticesWithRealRooms(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup)
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

    @defer.inlineCallbacks
    def test_server_notice_only_sent_once(self):
        self.store.get_monthly_active_count = Mock(return_value=1000)

        self.store.user_last_seen_monthly_active = Mock(return_value=1000)

        # Call the function multiple times to ensure we only send the notice once
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        # Now lets get the last load of messages in the service notice room and
        # check that there is only one server notice
        room_id = yield self.server_notices_manager.get_notice_room_for_user(
            self.user_id
        )

        token = yield self.event_source.get_current_token()
        events, _ = yield self.store.get_recent_events_for_room(
            room_id, limit=100, end_token=token.room_key
        )

        count = 0
        for event in events:
            if event.type != EventTypes.Message:
                continue
            if event.content.get("msgtype") != ServerNoticeMsgType:
                continue

            count += 1

        self.assertEqual(count, 1)
