# -*- coding: utf-8 -*-
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
from twisted.internet import defer

from synapse.api.errors import Codes, ResourceLimitError
from synapse.api.filtering import DEFAULT_FILTER_COLLECTION
from synapse.handlers.sync import SyncConfig, SyncHandler
from synapse.types import UserID

import tests.unittest
import tests.utils
from tests.utils import setup_test_homeserver


class SyncTestCase(tests.unittest.TestCase):
    """ Tests Sync Handler. """

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup)
        self.sync_handler = SyncHandler(self.hs)
        self.store = self.hs.get_datastore()

    @defer.inlineCallbacks
    def test_wait_for_sync_for_user_auth_blocking(self):

        user_id1 = "@user1:server"
        user_id2 = "@user2:server"
        sync_config = self._generate_sync_config(user_id1)

        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 1

        # Check that the happy case does not throw errors
        yield self.store.upsert_monthly_active_user(user_id1)
        yield self.sync_handler.wait_for_sync_for_user(sync_config)

        # Test that global lock works
        self.hs.config.hs_disabled = True
        with self.assertRaises(ResourceLimitError) as e:
            yield self.sync_handler.wait_for_sync_for_user(sync_config)
        self.assertEquals(e.exception.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

        self.hs.config.hs_disabled = False

        sync_config = self._generate_sync_config(user_id2)

        with self.assertRaises(ResourceLimitError) as e:
            yield self.sync_handler.wait_for_sync_for_user(sync_config)
        self.assertEquals(e.exception.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)

    def _generate_sync_config(self, user_id):
        return SyncConfig(
            user=UserID(user_id.split(":")[0][1:], user_id.split(":")[1]),
            filter_collection=DEFAULT_FILTER_COLLECTION,
            is_guest=False,
            request_key="request_key",
            device_id="device_id",
        )
