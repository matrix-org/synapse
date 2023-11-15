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

import abc
import logging
from typing import TYPE_CHECKING, Any, Mapping, Optional, Tuple, Type, cast, Generic

from synapse.storage.engines._base import (
    BaseDatabaseEngine,
    ConnectionType,
    CursorType,
    IncorrectDatabaseSetup,
    IsolationLevelType,
)
from synapse.storage.types import Cursor, DBAPI2Module

if TYPE_CHECKING:
    from synapse.storage.database import LoggingDatabaseConnection


logger = logging.getLogger(__name__)


class PostgresEngine(
    Generic[ConnectionType, CursorType, IsolationLevelType],
    BaseDatabaseEngine[ConnectionType, CursorType, IsolationLevelType],
    metaclass=abc.ABCMeta,
):
    isolation_level_map: Mapping[int, IsolationLevelType]
    default_isolation_level: IsolationLevelType

    def __init__(self, module: DBAPI2Module, database_config: Mapping[str, Any]):
        super().__init__(module, database_config)

        self.synchronous_commit: bool = database_config.get("synchronous_commit", True)
        # Set the statement timeout to 1 hour by default.
        # Any query taking more than 1 hour should probably be considered a bug;
        # most of the time this is a sign that work needs to be split up or that
        # some degenerate query plan has been created and the client has probably
        # timed out/walked off anyway.
        # This is in milliseconds.
        self.statement_timeout: Optional[int] = database_config.get(
            "statement_timeout", 60 * 60 * 1000
        )
        self._version: Optional[int] = None  # unknown as yet

        self.config = database_config

    @abc.abstractmethod
    def get_server_version(self, db_conn: ConnectionType) -> int:
        """Gets called when setting up a brand new database. This allows us to
        apply stricter checks on new databases versus existing database.
        """
        ...

    @abc.abstractmethod
    def set_statement_timeout(self, cursor: CursorType, statement_timeout: int) -> None:
        """Configure the current cursor's statement timeout."""
        ...

    @property
    def single_threaded(self) -> bool:
        return False

    def get_db_locale(self, txn: Cursor) -> Tuple[str, str]:
        txn.execute(
            "SELECT datcollate, datctype FROM pg_database WHERE datname = current_database()"
        )
        collation, ctype = cast(Tuple[str, str], txn.fetchone())
        return collation, ctype

    def check_database(
        self,
        db_conn: ConnectionType,
        allow_outdated_version: bool = False,
    ) -> None:
        # Get the version of PostgreSQL that we're using. As per the psycopg2
        # docs: The number is formed by converting the major, minor, and
        # revision numbers into two-decimal-digit numbers and appending them
        # together. For example, version 8.1.5 will be returned as 80105
        self._version = self.get_server_version(db_conn)
        allow_unsafe_locale = self.config.get("allow_unsafe_locale", False)

        # Are we on a supported PostgreSQL version?
        if not allow_outdated_version and self._version < 110000:
            raise RuntimeError("Synapse requires PostgreSQL 11 or above.")

        # psycopg and psycopg2 both support using cursors as context managers.
        with db_conn.cursor() as txn:  # type: ignore[attr-defined]
            txn.execute("SHOW SERVER_ENCODING")
            rows = txn.fetchall()
            if rows and rows[0][0] != "UTF8":
                raise IncorrectDatabaseSetup(
                    "Database has incorrect encoding: '%s' instead of 'UTF8'\n"
                    "See docs/postgres.md for more information." % (rows[0][0],)
                )

            collation, ctype = self.get_db_locale(txn)
            if collation != "C":
                logger.warning(
                    "Database has incorrect collation of %r. Should be 'C'",
                    collation,
                )
                if not allow_unsafe_locale:
                    raise IncorrectDatabaseSetup(
                        "Database has incorrect collation of %r. Should be 'C'\n"
                        "See docs/postgres.md for more information. You can override this check by"
                        "setting 'allow_unsafe_locale' to true in the database config.",
                        collation,
                    )

            if ctype != "C":
                if not allow_unsafe_locale:
                    logger.warning(
                        "Database has incorrect ctype of %r. Should be 'C'",
                        ctype,
                    )
                    raise IncorrectDatabaseSetup(
                        "Database has incorrect ctype of %r. Should be 'C'\n"
                        "See docs/postgres.md for more information. You can override this check by"
                        "setting 'allow_unsafe_locale' to true in the database config.",
                        ctype,
                    )

    def check_new_database(self, txn: Cursor) -> None:
        """Gets called when setting up a brand new database. This allows us to
        apply stricter checks on new databases versus existing database.
        """

        collation, ctype = self.get_db_locale(txn)

        errors = []

        if collation != "C":
            errors.append("    - 'COLLATE' is set to %r. Should be 'C'" % (collation,))

        if ctype != "C":
            errors.append("    - 'CTYPE' is set to %r. Should be 'C'" % (ctype,))

        if errors:
            raise IncorrectDatabaseSetup(
                "Database is incorrectly configured:\n\n%s\n\n"
                "See docs/postgres.md for more information." % ("\n".join(errors))
            )

    def convert_param_style(self, sql: str) -> str:
        return sql.replace("?", "%s")

    def on_new_connection(self, db_conn: "LoggingDatabaseConnection") -> None:
        # mypy doesn't realize that ConnectionType matches the Connection protocol.
        self.attempt_to_set_isolation_level(db_conn.conn, self.default_isolation_level)  # type: ignore[arg-type]

        # Set the bytea output to escape, vs the default of hex
        cursor = db_conn.cursor()
        cursor.execute("SET bytea_output TO escape")

        # Asynchronous commit, don't wait for the server to call fsync before
        # ending the transaction.
        # https://www.postgresql.org/docs/current/static/wal-async-commit.html
        if not self.synchronous_commit:
            cursor.execute("SET synchronous_commit TO OFF")

        # Abort really long-running statements and turn them into errors.
        if self.statement_timeout is not None:
            self.set_statement_timeout(cursor.txn, self.statement_timeout)  # type: ignore[arg-type]

        cursor.close()
        db_conn.commit()

    @property
    def supports_using_any_list(self) -> bool:
        """Do we support using `a = ANY(?)` and passing a list"""
        return True

    @property
    def supports_returning(self) -> bool:
        """Do we support the `RETURNING` clause in insert/update/delete?"""
        return True

    def is_connection_closed(self, conn: ConnectionType) -> bool:
        # Both psycopg and psycopg2 connections have a closed attributed.
        return bool(conn.closed)  # type: ignore[attr-defined]

    def lock_table(self, txn: Cursor, table: str) -> None:
        txn.execute("LOCK TABLE %s in EXCLUSIVE MODE" % (table,))

    @property
    def server_version(self) -> str:
        """Returns a string giving the server version. For example: '8.1.5'."""
        # note that this is a bit of a hack because it relies on check_database
        # having been called. Still, that should be a safe bet here.
        numver = self._version
        assert numver is not None

        # https://www.postgresql.org/docs/current/libpq-status.html#LIBPQ-PQSERVERVERSION
        if numver >= 100000:
            return "%i.%i" % (numver / 10000, numver % 10000)
        else:
            return "%i.%i.%i" % (numver / 10000, (numver % 10000) / 100, numver % 100)

    @property
    def row_id_name(self) -> str:
        return "ctid"

    @staticmethod
    def executescript(cursor: CursorType, script: str) -> None:
        """Execute a chunk of SQL containing multiple semicolon-delimited statements.

        Psycopg2 seems happy to do this in DBAPI2's `execute()` function.

        For consistency with SQLite, any ongoing transaction is committed before
        executing the script in its own transaction. The script transaction is
        left open and it is the responsibility of the caller to commit it.
        """
        cursor.execute(f"COMMIT; BEGIN TRANSACTION; {script}")
