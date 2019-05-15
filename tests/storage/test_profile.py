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


from twisted.internet import defer

from synapse.storage.profile import ProfileStore
from synapse.types import UserID

from tests import unittest
from tests.utils import setup_test_homeserver


class ProfileStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(self.addCleanup)

        self.store = ProfileStore(hs.get_db_conn(), hs)

        self.u_frank = UserID.from_string("@frank:test")

    @defer.inlineCallbacks
    def test_displayname(self):
        yield self.store.create_profile(self.u_frank.localpart)

        yield self.store.set_profile_displayname(self.u_frank.localpart, "Frank")

        self.assertEquals(
            "Frank", (yield self.store.get_profile_displayname(self.u_frank.localpart))
        )

    @defer.inlineCallbacks
    def test_avatar_url(self):
        yield self.store.create_profile(self.u_frank.localpart)

        yield self.store.set_profile_avatar_url(
            self.u_frank.localpart, "http://my.site/here"
        )

        self.assertEquals(
            "http://my.site/here",
            (yield self.store.get_profile_avatar_url(self.u_frank.localpart)),
        )
