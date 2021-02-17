# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
import platform
import struct
import threading
import typing

from synapse.storage.engines import BaseDatabaseEngine
from synapse.storage.types import Connection

if typing.TYPE_CHECKING:
    import sqlite3  # noqa: F401


class Sqlite3Engine(BaseDatabaseEngine["sqlite3.Connection"]):
    def __init__(self, database_module, database_config):
        super().__init__(database_module, database_config)

        database = database_config.get("args", {}).get("database")
        self._is_in_memory = database in (
            None,
            ":memory:",
        )

        if platform.python_implementation() == "PyPy":
            # pypy's sqlite3 module doesn't handle bytearrays, convert them
            # back to bytes.
            database_module.register_adapter(bytearray, lambda array: bytes(array))

        # The current max state_group, or None if we haven't looked
        # in the DB yet.
        self._current_state_group_id = None
        self._current_state_group_id_lock = threading.Lock()

    @property
    def single_threaded(self) -> bool:
        return True

    @property
    def can_native_upsert(self):
        """
        Do we support native UPSERTs? This requires SQLite3 3.24+, plus some
        more work we haven't done yet to tell what was inserted vs updated.
        """
        return self.module.sqlite_version_info >= (3, 24, 0)

    @property
    def supports_tuple_comparison(self):
        """
        Do we support comparing tuples, i.e. `(a, b) > (c, d)`? This requires
        SQLite 3.15+.
        """
        return self.module.sqlite_version_info >= (3, 15, 0)

    @property
    def supports_using_any_list(self):
        """Do we support using `a = ANY(?)` and passing a list"""
        return False

    def check_database(self, db_conn, allow_outdated_version: bool = False):
        if not allow_outdated_version:
            version = self.module.sqlite_version_info
            if version < (3, 11, 0):
                raise RuntimeError("Synapse requires sqlite 3.11 or above.")

    def check_new_database(self, txn):
        """Gets called when setting up a brand new database. This allows us to
        apply stricter checks on new databases versus existing database.
        """

    def convert_param_style(self, sql):
        return sql

    def on_new_connection(self, db_conn):
        # We need to import here to avoid an import loop.
        from synapse.storage.prepare_database import prepare_database

        if self._is_in_memory:
            # In memory databases need to be rebuilt each time. Ideally we'd
            # reuse the same connection as we do when starting up, but that
            # would involve using adbapi before we have started the reactor.
            prepare_database(db_conn, self, config=None)

        db_conn.create_function("rank", 1, _rank)
        db_conn.execute("PRAGMA foreign_keys = ON;")
        db_conn.commit()

    def is_deadlock(self, error):
        return False

    def is_connection_closed(self, conn):
        return False

    def lock_table(self, txn, table):
        return

    @property
    def server_version(self):
        """Gets a string giving the server version. For example: '3.22.0'

        Returns:
            string
        """
        return "%i.%i.%i" % self.module.sqlite_version_info

    def in_transaction(self, conn: Connection) -> bool:
        return conn.in_transaction  # type: ignore

    def attempt_to_set_autocommit(self, conn: Connection, autocommit: bool):
        # Twisted doesn't let us set attributes on the connections, so we can't
        # set the connection to autocommit mode.
        pass


# Following functions taken from: https://github.com/coleifer/peewee


def _parse_match_info(buf):
    bufsize = len(buf)
    return [struct.unpack("@I", buf[i : i + 4])[0] for i in range(0, bufsize, 4)]


def _rank(raw_match_info):
    """Handle match_info called w/default args 'pcx' - based on the example rank
    function http://sqlite.org/fts3.html#appendix_a
    """
    match_info = _parse_match_info(raw_match_info)
    score = 0.0
    p, c = match_info[:2]
    for phrase_num in range(p):
        phrase_info_idx = 2 + (phrase_num * c * 3)
        for col_num in range(c):
            col_idx = phrase_info_idx + (col_num * 3)
            x1, x2 = match_info[col_idx : col_idx + 2]
            if x1 > 0:
                score += float(x1) / x2
    return score
