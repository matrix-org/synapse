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

from mock import Mock, call
from twisted.enterprise.adbapi import ConnectionPool

from synapse.server import HomeServer
from synapse.storage import prepare_database
from synapse.storage.profile import ProfileStore


class SQLiteMemoryDbPool(ConnectionPool, object):
    def __init__(self):
        super(SQLiteMemoryDbPool, self).__init__(
            "sqlite3", ":memory:",
            cp_min=1,
            cp_max=1,
        )

    def prepare(self):
        return self.runWithConnection(prepare_database)

    #def runInteraction(self, interaction, *args, **kwargs):
    #    # Just use a cursor as the txn directly
    #    txn = self.db.cursor()

    #    def _on_success(result):
    #        txn.commit()
    #        return result
    #    def _on_failure(failure):
    #        txn.rollback()
    #        raise failure

    #    d = interaction(txn, *args, **kwargs)
    #    d.addCallbacks(_on_success, _on_failure)
    #    return d


class ProfileStoreTestCase(unittest.TestCase):
    def setUp(self):
        hs = HomeServer("test",
            db_pool=SQLiteMemoryDbPool(),
        )
        hs.get_db_pool().prepare()

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
