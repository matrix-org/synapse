# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

USER_ID = "@user:example.com"


class EventPushActionsStoreTestCase(tests.unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def test_get_unread_push_actions_for_user_in_range_for_http(self):
        yield self.store.get_unread_push_actions_for_user_in_range_for_http(
            USER_ID, 0, 1000, 20
        )

    @defer.inlineCallbacks
    def test_get_unread_push_actions_for_user_in_range_for_email(self):
        yield self.store.get_unread_push_actions_for_user_in_range_for_email(
            USER_ID, 0, 1000, 20
        )
