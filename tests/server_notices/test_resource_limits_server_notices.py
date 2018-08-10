from mock import Mock

from twisted.internet import defer

from synapse.api.errors import AuthError
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
        self.hs = yield setup_test_homeserver(handlers=None)
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
        self._send_notice = self._rlsn._server_notices_manager.send_notice

        self._rlsn._limit_usage_by_mau = True
        self.user_id = "user_id"

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_flag_off(self):
        """Tests cases where the flags indicate nothing to do"""
        # test hs disabled case
        self._hs_disabled = True

        yield self._rlsn.maybe_send_server_notice_to_user("user_id")

        self._send_notice.assert_not_called()
        # Test when mau limiting disabled
        self._hs_disabled = False
        self._rlsn._limit_usage_by_mau = False
        yield self._rlsn.maybe_send_server_notice_to_user("user_id")

        self._send_notice.assert_not_called()

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_remove_blocked_notice(self):
        """Test when user has blocked notice, but should have it removed"""

        self._rlsn._notified_of_blocking.add(self.user_id)
        self._rlsn.auth.check_auth_blocking = Mock()

        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)
        # "remove warning" obviously aweful, but test will start failing when code
        # actually sends a real event, and then it can be updated

        self._send_notice.assert_called_once_with(self.user_id, "remove warning")
        self.assertFalse(self.user_id in self._rlsn._notified_of_blocking)

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_remove_blocked_notice_noop(self):
        """Test when user has blocked notice, but notice ought to be there (NOOP)"""
        self._rlsn._notified_of_blocking.add(self.user_id)
        self._rlsn.auth.check_auth_blocking = Mock(
            side_effect=AuthError(403, 'foo')
        )

        yield self._rlsn.maybe_send_server_notice_to_user("user_id")

        self._send_notice.assert_not_called()
        self.assertTrue(self.user_id in self._rlsn._notified_of_blocking)

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_add_blocked_notice(self):
        """Test when user does not have blocked notice, but should have one"""

        self._rlsn.auth.check_auth_blocking = Mock(side_effect=AuthError(403, 'foo'))
        yield self._rlsn.maybe_send_server_notice_to_user("user_id")

        # "add warning" obviously awful, but test will start failing when code
        # actually sends a real event, and then it can be updated
        self._send_notice.assert_called_once_with(self.user_id, "add warning")
        self.assertTrue(self.user_id in self._rlsn._notified_of_blocking)

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_add_blocked_notice_noop(self):
        """Test when user does not have blocked notice, nor should they (NOOP)"""

        self._rlsn.auth.check_auth_blocking = Mock()

        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()
        self.assertFalse(self.user_id in self._rlsn._notified_of_blocking)

    @defer.inlineCallbacks
    def test_maybe_send_server_notice_to_user_not_in_mau_cohort(self):

        """Test when user is not part of the MAU cohort - this should not ever
        happen - but ...
        """

        self._rlsn.auth.check_auth_blocking = Mock()
        self._rlsn._store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(None)
        )
        yield self._rlsn.maybe_send_server_notice_to_user(self.user_id)

        self._send_notice.assert_not_called()
        self.assertFalse(self.user_id in self._rlsn._notified_of_blocking)
