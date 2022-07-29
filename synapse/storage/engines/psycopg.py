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

import logging
from typing import TYPE_CHECKING, Any, Mapping, NoReturn, Optional, Tuple, cast

import psycopg2.extensions

from synapse.storage.engines._base import (
    BaseDatabaseEngine,
    IncorrectDatabaseSetup,
    IsolationLevel,
)
from synapse.storage.types import Cursor

if TYPE_CHECKING:
    from synapse.storage.database import LoggingDatabaseConnection


logger = logging.getLogger(__name__)


class PostgresEngine(BaseDatabaseEngine[psycopg2.extensions.connection]):
    def __init__(self, database_config: Mapping[str, Any]):
        super().__init__(psycopg2, database_config)
        psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)

        # Disables passing `bytes` to txn.execute, c.f. #6186. If you do
        # actually want to use bytes than wrap it in `bytearray`.
        def _disable_bytes_adapter(_: bytes) -> NoReturn:
            raise Exception("Passing bytes to DB is disabled.")

        psycopg2.extensions.register_adapter(bytes, _disable_bytes_adapter)
        self.synchronous_commit: bool = database_config.get("synchronous_commit", True)
        self._version: Optional[int] = None  # unknown as yet

        self.isolation_level_map: Mapping[int, int] = {
            IsolationLevel.READ_COMMITTED: psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED,
            IsolationLevel.REPEATABLE_READ: psycopg2.extensions.ISOLATION_LEVEL_REPEATABLE_READ,
            IsolationLevel.SERIALIZABLE: psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE,
        }
        self.default_isolation_level = (
            psycopg2.extensions.ISOLATION_LEVEL_REPEATABLE_READ
        )
        self.config = database_config

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
        db_conn: psycopg2.extensions.connection,
        allow_outdated_version: bool = False,
    ) -> None:
        # Get the version of PostgreSQL that we're using. As per the psycopg2
        # docs: The number is formed by converting the major, minor, and
        # revision numbers into two-decimal-digit numbers and appending them
        # together. For example, version 8.1.5 will be returned as 80105
        self._version = cast(int, db_conn.server_version)
        allow_unsafe_locale = self.config.get("allow_unsafe_locale", False)

        # Are we on a supported PostgreSQL version?
        if not allow_outdated_version and self._version < 100000:
            raise RuntimeError("Synapse requires PostgreSQL 10 or above.")

        with db_conn.cursor() as txn:
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
        db_conn.set_isolation_level(self.default_isolation_level)

        # Set the bytea output to escape, vs the default of hex
        cursor = db_conn.cursor()
        cursor.execute("SET bytea_output TO escape")

        # Asynchronous commit, don't wait for the server to call fsync before
        # ending the transaction.
        # https://www.postgresql.org/docs/current/static/wal-async-commit.html
        if not self.synchronous_commit:
            cursor.execute("SET synchronous_commit TO OFF")

        cursor.close()
        db_conn.commit()

    @property
    def can_native_upsert(self) -> bool:
        """
        Can we use native UPSERTs?
        """
        return True

    @property
    def supports_using_any_list(self) -> bool:
        """Do we support using `a = ANY(?)` and passing a list"""
        return True

    @property
    def supports_returning(self) -> bool:
        """Do we support the `RETURNING` clause in insert/update/delete?"""
        return True

    def is_deadlock(self, error: Exception) -> bool:
        if isinstance(error, psycopg2.DatabaseError):
            # https://www.postgresql.org/docs/current/static/errcodes-appendix.html
            # "40001" serialization_failure
            # "40P01" deadlock_detected
            return error.pgcode in ["40001", "40P01"]
        return False

    def is_connection_closed(self, conn: psycopg2.extensions.connection) -> bool:
        return bool(conn.closed)

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

    def in_transaction(self, conn: psycopg2.extensions.connection) -> bool:
        return conn.status != psycopg2.extensions.STATUS_READY

    def attempt_to_set_autocommit(
        self, conn: psycopg2.extensions.connection, autocommit: bool
    ) -> None:
        return conn.set_session(autocommit=autocommit)

    def attempt_to_set_isolation_level(
        self, conn: psycopg2.extensions.connection, isolation_level: Optional[int]
    ) -> None:
        if isolation_level is None:
            isolation_level = self.default_isolation_level
        else:
            isolation_level = self.isolation_level_map[isolation_level]
        return conn.set_isolation_level(isolation_level)
