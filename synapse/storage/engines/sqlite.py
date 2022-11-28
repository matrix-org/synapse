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
import sqlite3
import struct
import threading
from typing import TYPE_CHECKING, Any, List, Mapping, Optional

from synapse.storage.engines import BaseDatabaseEngine
from synapse.storage.types import Cursor

if TYPE_CHECKING:
    from synapse.storage.database import LoggingDatabaseConnection


class Sqlite3Engine(BaseDatabaseEngine[sqlite3.Connection, sqlite3.Cursor]):
    def __init__(self, database_config: Mapping[str, Any]):
        super().__init__(sqlite3, database_config)

        database = database_config.get("args", {}).get("database")
        self._is_in_memory = database in (
            None,
            ":memory:",
        )

        if platform.python_implementation() == "PyPy":
            # pypy's sqlite3 module doesn't handle bytearrays, convert them
            # back to bytes.
            sqlite3.register_adapter(bytearray, lambda array: bytes(array))

        # The current max state_group, or None if we haven't looked
        # in the DB yet.
        self._current_state_group_id = None
        self._current_state_group_id_lock = threading.Lock()

    @property
    def single_threaded(self) -> bool:
        return True

    @property
    def supports_using_any_list(self) -> bool:
        """Do we support using `a = ANY(?)` and passing a list"""
        return False

    @property
    def supports_returning(self) -> bool:
        """Do we support the `RETURNING` clause in insert/update/delete?"""
        return sqlite3.sqlite_version_info >= (3, 35, 0)

    def check_database(
        self, db_conn: sqlite3.Connection, allow_outdated_version: bool = False
    ) -> None:
        if not allow_outdated_version:
            # Synapse is untested against older SQLite versions, and we don't want
            # to let users upgrade to a version of Synapse with broken support for their
            # sqlite version, because it risks leaving them with a half-upgraded db.
            if sqlite3.sqlite_version_info < (3, 27, 0):
                raise RuntimeError("Synapse requires sqlite 3.27 or above.")

    def check_new_database(self, txn: Cursor) -> None:
        """Gets called when setting up a brand new database. This allows us to
        apply stricter checks on new databases versus existing database.
        """

    def convert_param_style(self, sql: str) -> str:
        return sql

    def on_new_connection(self, db_conn: "LoggingDatabaseConnection") -> None:
        # We need to import here to avoid an import loop.
        from synapse.storage.prepare_database import prepare_database

        if self._is_in_memory:
            # In memory databases need to be rebuilt each time. Ideally we'd
            # reuse the same connection as we do when starting up, but that
            # would involve using adbapi before we have started the reactor.
            prepare_database(db_conn, self, config=None)

        db_conn.create_function("rank", 1, _rank)
        db_conn.execute("PRAGMA foreign_keys = ON;")

        # Enable WAL.
        # see https://www.sqlite.org/wal.html
        db_conn.execute("PRAGMA journal_mode = WAL;")
        db_conn.commit()

    def is_deadlock(self, error: Exception) -> bool:
        return False

    def is_connection_closed(self, conn: sqlite3.Connection) -> bool:
        return False

    def lock_table(self, txn: Cursor, table: str) -> None:
        return

    @property
    def server_version(self) -> str:
        """Gets a string giving the server version. For example: '3.22.0'."""
        return "%i.%i.%i" % sqlite3.sqlite_version_info

    def in_transaction(self, conn: sqlite3.Connection) -> bool:
        return conn.in_transaction

    def attempt_to_set_autocommit(
        self, conn: sqlite3.Connection, autocommit: bool
    ) -> None:
        # Twisted doesn't let us set attributes on the connections, so we can't
        # set the connection to autocommit mode.
        pass

    def attempt_to_set_isolation_level(
        self, conn: sqlite3.Connection, isolation_level: Optional[int]
    ) -> None:
        # All transactions are SERIALIZABLE by default in sqlite
        pass

    @staticmethod
    def executescript(cursor: sqlite3.Cursor, script: str) -> None:
        """Execute a chunk of SQL containing multiple semicolon-delimited statements.

        Python's built-in SQLite driver does not allow you to do this with DBAPI2's
        `execute`:

        > execute() will only execute a single SQL statement. If you try to execute more
        > than one statement with it, it will raise a Warning. Use executescript() if
        > you want to execute multiple SQL statements with one call.

        Though the docs for `executescript` warn:

        > If there is a pending transaction, an implicit COMMIT statement is executed
        > first. No other implicit transaction control is performed; any transaction
        > control must be added to sql_script.
        """
        cursor.executescript(script)


# Following functions taken from: https://github.com/coleifer/peewee


def _parse_match_info(buf: bytes) -> List[int]:
    bufsize = len(buf)
    return [struct.unpack("@I", buf[i : i + 4])[0] for i in range(0, bufsize, 4)]


def _rank(raw_match_info: bytes) -> float:
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
