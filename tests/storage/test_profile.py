# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


from twisted.trial import unittest
from twisted.internet import defer

from synapse.server import HomeServer
from synapse.storage.profile import ProfileStore

from tests.utils import SQLiteMemoryDbPool


class ProfileStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        hs = HomeServer("test",
            db_pool=db_pool,
        )

        self.store = ProfileStore(hs)

        self.u_frank = hs.parse_userid("@frank:test")

    @defer.inlineCallbacks
    def test_displayname(self):
        yield self.store.create_profile(
            self.u_frank.localpart
        )

        yield self.store.set_profile_displayname(
            self.u_frank.localpart, "Frank"
        )

        name = yield self.store.get_profile_displayname(self.u_frank.localpart)

        self.assertEquals("Frank", name)

    @defer.inlineCallbacks
    def test_avatar_url(self):
        yield self.store.create_profile(
            self.u_frank.localpart
        )

        yield self.store.set_profile_avatar_url(
                self.u_frank.localpart, "http://my.site/here"
        )

        name = yield self.store.get_profile_avatar_url(self.u_frank.localpart)

        self.assertEquals("http://my.site/here", name)
