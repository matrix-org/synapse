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


from collections import OrderedDict

from mock import Mock

from twisted.internet import defer

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import Database
from synapse.storage.engines import create_engine

from tests import unittest
from tests.utils import TestHomeServer


class SQLBaseStoreTestCase(unittest.TestCase):
    """ Test the "simple" SQL generating methods in SQLBaseStore. """

    def setUp(self):
        self.db_pool = Mock(spec=["runInteraction"])
        self.mock_txn = Mock()
        self.mock_conn = Mock(spec_set=["cursor", "rollback", "commit"])
        self.mock_conn.cursor.return_value = self.mock_txn
        self.mock_conn.rollback.return_value = None
        # Our fake runInteraction just runs synchronously inline

        def runInteraction(func, *args, **kwargs):
            return defer.succeed(func(self.mock_txn, *args, **kwargs))

        self.db_pool.runInteraction = runInteraction

        def runWithConnection(func, *args, **kwargs):
            return defer.succeed(func(self.mock_conn, *args, **kwargs))

        self.db_pool.runWithConnection = runWithConnection

        config = Mock()
        config._disable_native_upserts = True
        config.caches = Mock()
        config.caches.event_cache_size = 1
        hs = TestHomeServer("test", config=config)

        sqlite_config = {"name": "sqlite3"}
        engine = create_engine(sqlite_config)
        fake_engine = Mock(wraps=engine)
        fake_engine.can_native_upsert = False

        db = Database(Mock(), Mock(config=sqlite_config), fake_engine)
        db._db_pool = self.db_pool

        self.datastore = SQLBaseStore(db, None, hs)

    @defer.inlineCallbacks
    def test_insert_1col(self):
        self.mock_txn.rowcount = 1

        yield self.datastore.db.simple_insert(
            table="tablename", values={"columname": "Value"}
        )

        self.mock_txn.execute.assert_called_with(
            "INSERT INTO tablename (columname) VALUES(?)", ("Value",)
        )

    @defer.inlineCallbacks
    def test_insert_3cols(self):
        self.mock_txn.rowcount = 1

        yield self.datastore.db.simple_insert(
            table="tablename",
            # Use OrderedDict() so we can assert on the SQL generated
            values=OrderedDict([("colA", 1), ("colB", 2), ("colC", 3)]),
        )

        self.mock_txn.execute.assert_called_with(
            "INSERT INTO tablename (colA, colB, colC) VALUES(?, ?, ?)", (1, 2, 3)
        )

    @defer.inlineCallbacks
    def test_select_one_1col(self):
        self.mock_txn.rowcount = 1
        self.mock_txn.__iter__ = Mock(return_value=iter([("Value",)]))

        value = yield self.datastore.db.simple_select_one_onecol(
            table="tablename", keyvalues={"keycol": "TheKey"}, retcol="retcol"
        )

        self.assertEquals("Value", value)
        self.mock_txn.execute.assert_called_with(
            "SELECT retcol FROM tablename WHERE keycol = ?", ["TheKey"]
        )

    @defer.inlineCallbacks
    def test_select_one_3col(self):
        self.mock_txn.rowcount = 1
        self.mock_txn.fetchone.return_value = (1, 2, 3)

        ret = yield self.datastore.db.simple_select_one(
            table="tablename",
            keyvalues={"keycol": "TheKey"},
            retcols=["colA", "colB", "colC"],
        )

        self.assertEquals({"colA": 1, "colB": 2, "colC": 3}, ret)
        self.mock_txn.execute.assert_called_with(
            "SELECT colA, colB, colC FROM tablename WHERE keycol = ?", ["TheKey"]
        )

    @defer.inlineCallbacks
    def test_select_one_missing(self):
        self.mock_txn.rowcount = 0
        self.mock_txn.fetchone.return_value = None

        ret = yield self.datastore.db.simple_select_one(
            table="tablename",
            keyvalues={"keycol": "Not here"},
            retcols=["colA"],
            allow_none=True,
        )

        self.assertFalse(ret)

    @defer.inlineCallbacks
    def test_select_list(self):
        self.mock_txn.rowcount = 3
        self.mock_txn.__iter__ = Mock(return_value=iter([(1,), (2,), (3,)]))
        self.mock_txn.description = (("colA", None, None, None, None, None, None),)

        ret = yield self.datastore.db.simple_select_list(
            table="tablename", keyvalues={"keycol": "A set"}, retcols=["colA"]
        )

        self.assertEquals([{"colA": 1}, {"colA": 2}, {"colA": 3}], ret)
        self.mock_txn.execute.assert_called_with(
            "SELECT colA FROM tablename WHERE keycol = ?", ["A set"]
        )

    @defer.inlineCallbacks
    def test_update_one_1col(self):
        self.mock_txn.rowcount = 1

        yield self.datastore.db.simple_update_one(
            table="tablename",
            keyvalues={"keycol": "TheKey"},
            updatevalues={"columnname": "New Value"},
        )

        self.mock_txn.execute.assert_called_with(
            "UPDATE tablename SET columnname = ? WHERE keycol = ?",
            ["New Value", "TheKey"],
        )

    @defer.inlineCallbacks
    def test_update_one_4cols(self):
        self.mock_txn.rowcount = 1

        yield self.datastore.db.simple_update_one(
            table="tablename",
            keyvalues=OrderedDict([("colA", 1), ("colB", 2)]),
            updatevalues=OrderedDict([("colC", 3), ("colD", 4)]),
        )

        self.mock_txn.execute.assert_called_with(
            "UPDATE tablename SET colC = ?, colD = ? WHERE" " colA = ? AND colB = ?",
            [3, 4, 1, 2],
        )

    @defer.inlineCallbacks
    def test_delete_one(self):
        self.mock_txn.rowcount = 1

        yield self.datastore.db.simple_delete_one(
            table="tablename", keyvalues={"keycol": "Go away"}
        )

        self.mock_txn.execute.assert_called_with(
            "DELETE FROM tablename WHERE keycol = ?", ["Go away"]
        )
