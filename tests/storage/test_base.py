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
from typing import Generator
from unittest.mock import Mock, call, patch

from twisted.internet import defer

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool
from synapse.storage.engines import create_engine

from tests import unittest
from tests.server import TestHomeServer
from tests.utils import USE_POSTGRES_FOR_TESTS, default_config


class SQLBaseStoreTestCase(unittest.TestCase):
    """Test the "simple" SQL generating methods in SQLBaseStore."""

    def setUp(self) -> None:
        # This is the Twisted connection pool.
        conn_pool = Mock(spec=["runInteraction", "runWithConnection"])
        self.mock_txn = Mock()
        if USE_POSTGRES_FOR_TESTS:
            # To avoid testing psycopg2 itself, patch execute_batch/execute_values
            # to assert how it is called.
            from psycopg2 import extras

            self.mock_execute_batch = Mock()
            self.execute_batch_patcher = patch.object(
                extras, "execute_batch", new=self.mock_execute_batch
            )
            self.execute_batch_patcher.start()
            self.mock_execute_values = Mock()
            self.execute_values_patcher = patch.object(
                extras, "execute_values", new=self.mock_execute_values
            )
            self.execute_values_patcher.start()

            self.mock_conn = Mock(
                spec_set=[
                    "cursor",
                    "rollback",
                    "commit",
                    "closed",
                    "reconnect",
                    "set_session",
                    "encoding",
                ]
            )
            self.mock_conn.encoding = "UNICODE"
        else:
            self.mock_conn = Mock(spec_set=["cursor", "rollback", "commit"])
        self.mock_conn.cursor.return_value = self.mock_txn
        self.mock_txn.connection = self.mock_conn
        self.mock_conn.rollback.return_value = None
        # Our fake runInteraction just runs synchronously inline

        def runInteraction(func, *args, **kwargs) -> defer.Deferred:  # type: ignore[no-untyped-def]
            return defer.succeed(func(self.mock_txn, *args, **kwargs))

        conn_pool.runInteraction = runInteraction

        def runWithConnection(func, *args, **kwargs):  # type: ignore[no-untyped-def]
            return defer.succeed(func(self.mock_conn, *args, **kwargs))

        conn_pool.runWithConnection = runWithConnection

        config = default_config(name="test", parse=True)
        hs = TestHomeServer("test", config=config)

        if USE_POSTGRES_FOR_TESTS:
            db_config = {"name": "psycopg2", "args": {}}
        else:
            db_config = {"name": "sqlite3"}
        engine = create_engine(db_config)

        fake_engine = Mock(wraps=engine)
        fake_engine.in_transaction.return_value = False
        fake_engine.module.OperationalError = engine.module.OperationalError
        fake_engine.module.DatabaseError = engine.module.DatabaseError
        fake_engine.module.IntegrityError = engine.module.IntegrityError
        # Don't convert param style to make assertions easier.
        fake_engine.convert_param_style = lambda sql: sql
        # To fix isinstance(...) checks.
        fake_engine.__class__ = engine.__class__  # type: ignore[assignment]

        db = DatabasePool(Mock(), Mock(config=db_config), fake_engine)
        db._db_pool = conn_pool

        self.datastore = SQLBaseStore(db, None, hs)  # type: ignore[arg-type]

    def tearDown(self) -> None:
        if USE_POSTGRES_FOR_TESTS:
            self.execute_batch_patcher.stop()
            self.execute_values_patcher.stop()

    @defer.inlineCallbacks
    def test_insert_1col(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_insert(
                table="tablename", values={"columname": "Value"}
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "INSERT INTO tablename (columname) VALUES(?)", ("Value",)
        )

    @defer.inlineCallbacks
    def test_insert_3cols(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_insert(
                table="tablename",
                # Use OrderedDict() so we can assert on the SQL generated
                values=OrderedDict([("colA", 1), ("colB", 2), ("colC", 3)]),
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "INSERT INTO tablename (colA, colB, colC) VALUES(?, ?, ?)", (1, 2, 3)
        )

    @defer.inlineCallbacks
    def test_insert_many(self) -> Generator["defer.Deferred[object]", object, None]:
        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_insert_many(
                table="tablename",
                keys=(
                    "col1",
                    "col2",
                ),
                values=[
                    (
                        "val1",
                        "val2",
                    ),
                    ("val3", "val4"),
                ],
                desc="",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_execute_values.assert_called_once_with(
                self.mock_txn,
                "INSERT INTO tablename (col1, col2) VALUES ?",
                [("val1", "val2"), ("val3", "val4")],
                template=None,
                fetch=False,
            )
        else:
            self.mock_txn.executemany.assert_called_once_with(
                "INSERT INTO tablename (col1, col2) VALUES(?, ?)",
                [("val1", "val2"), ("val3", "val4")],
            )

    @defer.inlineCallbacks
    def test_insert_many_no_iterable(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_insert_many(
                table="tablename",
                keys=(
                    "col1",
                    "col2",
                ),
                values=[],
                desc="",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_execute_values.assert_not_called()
        else:
            self.mock_txn.executemany.assert_not_called()

    @defer.inlineCallbacks
    def test_select_one_1col(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1
        self.mock_txn.__iter__ = Mock(return_value=iter([("Value",)]))

        value = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_select_one_onecol(
                table="tablename", keyvalues={"keycol": "TheKey"}, retcol="retcol"
            )
        )

        self.assertEqual("Value", value)
        self.mock_txn.execute.assert_called_once_with(
            "SELECT retcol FROM tablename WHERE keycol = ?", ["TheKey"]
        )

    @defer.inlineCallbacks
    def test_select_one_3col(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1
        self.mock_txn.fetchone.return_value = (1, 2, 3)

        ret = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_select_one(
                table="tablename",
                keyvalues={"keycol": "TheKey"},
                retcols=["colA", "colB", "colC"],
            )
        )

        self.assertEqual((1, 2, 3), ret)
        self.mock_txn.execute.assert_called_once_with(
            "SELECT colA, colB, colC FROM tablename WHERE keycol = ?", ["TheKey"]
        )

    @defer.inlineCallbacks
    def test_select_one_missing(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 0
        self.mock_txn.fetchone.return_value = None

        ret = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_select_one(
                table="tablename",
                keyvalues={"keycol": "Not here"},
                retcols=["colA"],
                allow_none=True,
            )
        )

        self.assertIsNone(ret)

    @defer.inlineCallbacks
    def test_select_list(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 3
        self.mock_txn.fetchall.return_value = [(1,), (2,), (3,)]
        self.mock_txn.description = (("colA", None, None, None, None, None, None),)

        ret = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_select_list(
                table="tablename", keyvalues={"keycol": "A set"}, retcols=["colA"]
            )
        )

        self.assertEqual([(1,), (2,), (3,)], ret)
        self.mock_txn.execute.assert_called_once_with(
            "SELECT colA FROM tablename WHERE keycol = ?", ["A set"]
        )

    @defer.inlineCallbacks
    def test_select_many_batch(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 3
        self.mock_txn.fetchall.side_effect = [[(1,), (2,)], [(3,)]]

        ret = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_select_many_batch(
                table="tablename",
                column="col1",
                iterable=("val1", "val2", "val3"),
                retcols=("col2",),
                keyvalues={"col3": "val4"},
                batch_size=2,
            )
        )

        self.mock_txn.execute.assert_has_calls(
            [
                call(
                    "SELECT col2 FROM tablename WHERE col1 = ANY(?) AND col3 = ?",
                    [["val1", "val2"], "val4"],
                ),
                call(
                    "SELECT col2 FROM tablename WHERE col1 = ANY(?) AND col3 = ?",
                    [["val3"], "val4"],
                ),
            ],
        )
        self.assertEqual([(1,), (2,), (3,)], ret)

    def test_select_many_no_iterable(self) -> None:
        self.mock_txn.rowcount = 3
        self.mock_txn.fetchall.side_effect = [(1,), (2,)]

        ret = self.datastore.db_pool.simple_select_many_txn(
            self.mock_txn,
            table="tablename",
            column="col1",
            iterable=(),
            retcols=("col2",),
            keyvalues={"col3": "val4"},
        )

        self.mock_txn.execute.assert_not_called()
        self.assertEqual([], ret)

    @defer.inlineCallbacks
    def test_update_one_1col(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_update_one(
                table="tablename",
                keyvalues={"keycol": "TheKey"},
                updatevalues={"columnname": "New Value"},
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "UPDATE tablename SET columnname = ? WHERE keycol = ?",
            ["New Value", "TheKey"],
        )

    @defer.inlineCallbacks
    def test_update_one_4cols(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_update_one(
                table="tablename",
                keyvalues=OrderedDict([("colA", 1), ("colB", 2)]),
                updatevalues=OrderedDict([("colC", 3), ("colD", 4)]),
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "UPDATE tablename SET colC = ?, colD = ? WHERE" " colA = ? AND colB = ?",
            [3, 4, 1, 2],
        )

    @defer.inlineCallbacks
    def test_update_many(self) -> Generator["defer.Deferred[object]", object, None]:
        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_update_many(
                table="tablename",
                key_names=("col1", "col2"),
                key_values=[("val1", "val2")],
                value_names=("col3",),
                value_values=[("val3",)],
                desc="",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_execute_batch.assert_called_once_with(
                self.mock_txn,
                "UPDATE tablename SET col3 = ? WHERE col1 = ? AND col2 = ?",
                [("val3", "val1", "val2")],
            )
        else:
            self.mock_txn.executemany.assert_called_once_with(
                "UPDATE tablename SET col3 = ? WHERE col1 = ? AND col2 = ?",
                [("val3", "val1", "val2")],
            )

        # key_values and value_values must be the same length.
        with self.assertRaises(ValueError):
            yield defer.ensureDeferred(
                self.datastore.db_pool.simple_update_many(
                    table="tablename",
                    key_names=("col1", "col2"),
                    key_values=[("val1", "val2")],
                    value_names=("col3",),
                    value_values=[],
                    desc="",
                )
            )

    @defer.inlineCallbacks
    def test_update_many_no_iterable(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_update_many(
                table="tablename",
                key_names=("col1", "col2"),
                key_values=[],
                value_names=("col3",),
                value_values=[],
                desc="",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_execute_batch.assert_not_called()
        else:
            self.mock_txn.executemany.assert_not_called()

    @defer.inlineCallbacks
    def test_delete_one(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_delete_one(
                table="tablename", keyvalues={"keycol": "Go away"}
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "DELETE FROM tablename WHERE keycol = ?", ["Go away"]
        )

    @defer.inlineCallbacks
    def test_delete_many(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 2

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_delete_many(
                table="tablename",
                column="col1",
                iterable=("val1", "val2"),
                keyvalues={"col2": "val3"},
                desc="",
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "DELETE FROM tablename WHERE col1 = ANY(?) AND col2 = ?",
            [["val1", "val2"], "val3"],
        )
        self.assertEqual(result, 2)

    @defer.inlineCallbacks
    def test_delete_many_no_iterable(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_delete_many(
                table="tablename",
                column="col1",
                iterable=(),
                keyvalues={"col2": "val3"},
                desc="",
            )
        )

        self.mock_txn.execute.assert_not_called()
        self.assertEqual(result, 0)

    @defer.inlineCallbacks
    def test_delete_many_no_keyvalues(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 2

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_delete_many(
                table="tablename",
                column="col1",
                iterable=("val1", "val2"),
                keyvalues={},
                desc="",
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "DELETE FROM tablename WHERE col1 = ANY(?)", [["val1", "val2"]]
        )
        self.assertEqual(result, 2)

    @defer.inlineCallbacks
    def test_upsert(self) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={"othercol": "newvalue"},
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "INSERT INTO tablename (columnname, othercol) VALUES (?, ?) ON CONFLICT (columnname) DO UPDATE SET othercol=EXCLUDED.othercol",
            ["oldvalue", "newvalue"],
        )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_no_values(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "value"},
                values={},
                insertion_values={"columnname": "value"},
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "INSERT INTO tablename (columnname) VALUES (?) ON CONFLICT (columnname) DO NOTHING",
            ["value"],
        )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_with_insertion(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={"othercol": "newvalue"},
                insertion_values={"thirdcol": "insertionval"},
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "INSERT INTO tablename (columnname, thirdcol, othercol) VALUES (?, ?, ?) ON CONFLICT (columnname) DO UPDATE SET othercol=EXCLUDED.othercol",
            ["oldvalue", "insertionval", "newvalue"],
        )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_with_where(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={"othercol": "newvalue"},
                where_clause="thirdcol IS NULL",
            )
        )

        self.mock_txn.execute.assert_called_once_with(
            "INSERT INTO tablename (columnname, othercol) VALUES (?, ?) ON CONFLICT (columnname) WHERE thirdcol IS NULL DO UPDATE SET othercol=EXCLUDED.othercol",
            ["oldvalue", "newvalue"],
        )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_many(self) -> Generator["defer.Deferred[object]", object, None]:
        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert_many(
                table="tablename",
                key_names=["keycol1", "keycol2"],
                key_values=[["keyval1", "keyval2"], ["keyval3", "keyval4"]],
                value_names=["valuecol3"],
                value_values=[["val5"], ["val6"]],
                desc="",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_execute_values.assert_called_once_with(
                self.mock_txn,
                "INSERT INTO tablename (keycol1, keycol2, valuecol3) VALUES ? ON CONFLICT (keycol1, keycol2) DO UPDATE SET valuecol3=EXCLUDED.valuecol3",
                [("keyval1", "keyval2", "val5"), ("keyval3", "keyval4", "val6")],
                template=None,
                fetch=False,
            )
        else:
            self.mock_txn.executemany.assert_called_once_with(
                "INSERT INTO tablename (keycol1, keycol2, valuecol3) VALUES (?, ?, ?) ON CONFLICT (keycol1, keycol2) DO UPDATE SET valuecol3=EXCLUDED.valuecol3",
                [("keyval1", "keyval2", "val5"), ("keyval3", "keyval4", "val6")],
            )

    @defer.inlineCallbacks
    def test_upsert_many_no_values(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert_many(
                table="tablename",
                key_names=["columnname"],
                key_values=[["oldvalue"]],
                value_names=[],
                value_values=[],
                desc="",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_execute_values.assert_called_once_with(
                self.mock_txn,
                "INSERT INTO tablename (columnname) VALUES ? ON CONFLICT (columnname) DO NOTHING",
                [("oldvalue",)],
                template=None,
                fetch=False,
            )
        else:
            self.mock_txn.executemany.assert_called_once_with(
                "INSERT INTO tablename (columnname) VALUES (?) ON CONFLICT (columnname) DO NOTHING",
                [("oldvalue",)],
            )

    @defer.inlineCallbacks
    def test_upsert_emulated_no_values_exists(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.datastore.db_pool._unsafe_to_upsert_tables.add("tablename")

        self.mock_txn.fetchall.return_value = [(1,)]

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "value"},
                values={},
                insertion_values={"columnname": "value"},
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_txn.execute.assert_has_calls(
                [
                    call("LOCK TABLE tablename in EXCLUSIVE MODE", ()),
                    call("SELECT 1 FROM tablename WHERE columnname = ?", ["value"]),
                ]
            )
        else:
            self.mock_txn.execute.assert_called_once_with(
                "SELECT 1 FROM tablename WHERE columnname = ?", ["value"]
            )
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_upsert_emulated_no_values_not_exists(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.datastore.db_pool._unsafe_to_upsert_tables.add("tablename")

        self.mock_txn.fetchall.return_value = []
        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "value"},
                values={},
                insertion_values={"columnname": "value"},
            )
        )

        self.mock_txn.execute.assert_has_calls(
            [
                call(
                    "SELECT 1 FROM tablename WHERE columnname = ?",
                    ["value"],
                ),
                call("INSERT INTO tablename (columnname) VALUES (?)", ["value"]),
            ],
        )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_emulated_with_insertion_exists(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.datastore.db_pool._unsafe_to_upsert_tables.add("tablename")

        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={"othercol": "newvalue"},
                insertion_values={"thirdcol": "insertionval"},
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_txn.execute.assert_has_calls(
                [
                    call("LOCK TABLE tablename in EXCLUSIVE MODE", ()),
                    call(
                        "UPDATE tablename SET othercol = ? WHERE columnname = ?",
                        ["newvalue", "oldvalue"],
                    ),
                ]
            )
        else:
            self.mock_txn.execute.assert_called_once_with(
                "UPDATE tablename SET othercol = ? WHERE columnname = ?",
                ["newvalue", "oldvalue"],
            )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_emulated_with_insertion_not_exists(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.datastore.db_pool._unsafe_to_upsert_tables.add("tablename")

        self.mock_txn.rowcount = 0

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={"othercol": "newvalue"},
                insertion_values={"thirdcol": "insertionval"},
            )
        )

        self.mock_txn.execute.assert_has_calls(
            [
                call(
                    "UPDATE tablename SET othercol = ? WHERE columnname = ?",
                    ["newvalue", "oldvalue"],
                ),
                call(
                    "INSERT INTO tablename (columnname, othercol, thirdcol) VALUES (?, ?, ?)",
                    ["oldvalue", "newvalue", "insertionval"],
                ),
            ]
        )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_emulated_with_where(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.datastore.db_pool._unsafe_to_upsert_tables.add("tablename")

        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={"othercol": "newvalue"},
                where_clause="thirdcol IS NULL",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_txn.execute.assert_has_calls(
                [
                    call("LOCK TABLE tablename in EXCLUSIVE MODE", ()),
                    call(
                        "UPDATE tablename SET othercol = ? WHERE columnname = ? AND thirdcol IS NULL",
                        ["newvalue", "oldvalue"],
                    ),
                ]
            )
        else:
            self.mock_txn.execute.assert_called_once_with(
                "UPDATE tablename SET othercol = ? WHERE columnname = ? AND thirdcol IS NULL",
                ["newvalue", "oldvalue"],
            )
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_upsert_emulated_with_where_no_values(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        self.datastore.db_pool._unsafe_to_upsert_tables.add("tablename")

        self.mock_txn.rowcount = 1

        result = yield defer.ensureDeferred(
            self.datastore.db_pool.simple_upsert(
                table="tablename",
                keyvalues={"columnname": "oldvalue"},
                values={},
                where_clause="thirdcol IS NULL",
            )
        )

        if USE_POSTGRES_FOR_TESTS:
            self.mock_txn.execute.assert_has_calls(
                [
                    call("LOCK TABLE tablename in EXCLUSIVE MODE", ()),
                    call(
                        "SELECT 1 FROM tablename WHERE columnname = ? AND thirdcol IS NULL",
                        ["oldvalue"],
                    ),
                ]
            )
        else:
            self.mock_txn.execute.assert_called_once_with(
                "SELECT 1 FROM tablename WHERE columnname = ? AND thirdcol IS NULL",
                ["oldvalue"],
            )
        self.assertFalse(result)
