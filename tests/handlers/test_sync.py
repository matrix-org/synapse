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

import tests.unittest
import tests.utils
from tests.utils import setup_test_homeserver
from synapse.handlers.sync import SyncHandler, SyncConfig
from synapse.types import UserID


class SyncTestCase(tests.unittest.TestCase):
    """ Tests Sync Handler. """

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver()
        self.sync_handler = SyncHandler(self.hs)

    @defer.inlineCallbacks
    def test_wait_for_sync_for_user_auth_blocking(self):
        sync_config = SyncConfig(
            user=UserID("@user","server"),
            filter_collection=None,
            is_guest=False,
            request_key="request_key",
            device_id="device_id",
        )
        res = yield self.sync_handler.wait_for_sync_for_user(sync_config)
        print res
