from twisted.internet import defer

from synapse.storage.monthly_active_users import MonthlyActiveUsersStore

import tests.unittest
import tests.utils
from tests.utils import setup_test_homeserver


class MonthlyActiveUsersTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(MonthlyActiveUsersTestCase, self).__init__(*args, **kwargs)
        self.mau = None

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver()
        self.mau = MonthlyActiveUsersStore(None, hs)

    @defer.inlineCallbacks
    def test_can_insert_and_count_mau(self):
        count = yield self.mau.get_monthly_active_count()
        self.assertEqual(0, count)

        yield self.mau.upsert_monthly_active_user("@user:server")
        count = yield self.mau.get_monthly_active_count()

        self.assertEqual(1, count)

    @defer.inlineCallbacks
    def test_is_user_monthly_active(self):
        user_id1 = "@user1:server"
        user_id2 = "@user2:server"
        user_id3 = "@user3:server"
        result = yield self.mau.is_user_monthly_active(user_id1)
        self.assertFalse(result)
        yield self.mau.upsert_monthly_active_user(user_id1)
        yield self.mau.upsert_monthly_active_user(user_id2)
        result = yield self.mau.is_user_monthly_active(user_id1)
        self.assertTrue(result)
        result = yield self.mau.is_user_monthly_active(user_id3)
        self.assertFalse(result)
