# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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


from tests import unittest
from twisted.internet import defer

from synapse.storage.presence import PresenceStore
from synapse.types import UserID

from tests.utils import setup_test_homeserver, MockClock


class PresenceStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(clock=MockClock())

        self.store = PresenceStore(hs)

        self.u_apple = UserID.from_string("@apple:test")
        self.u_banana = UserID.from_string("@banana:test")

    @defer.inlineCallbacks
    def test_presence_list(self):
        self.assertEquals(
            [],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
            ))
        )
        self.assertEquals(
            [],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
                accepted=True,
            ))
        )

        yield self.store.add_presence_list_pending(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )

        self.assertEquals(
            [{"observed_user_id": "@banana:test", "accepted": 0}],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
            ))
        )
        self.assertEquals(
            [],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
                accepted=True,
            ))
        )

        yield self.store.set_presence_list_accepted(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )

        self.assertEquals(
            [{"observed_user_id": "@banana:test", "accepted": 1}],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
            ))
        )
        self.assertEquals(
            [{"observed_user_id": "@banana:test", "accepted": 1}],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
                accepted=True,
            ))
        )

        yield self.store.del_presence_list(
            observer_localpart=self.u_apple.localpart,
            observed_userid=self.u_banana.to_string(),
        )

        self.assertEquals(
            [],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
            ))
        )
        self.assertEquals(
            [],
            (yield self.store.get_presence_list(
                observer_localpart=self.u_apple.localpart,
                accepted=True,
            ))
        )
