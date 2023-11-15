# Copyright 2022-2023 The Matrix.org Foundation C.I.C.
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
from typing import Any, Mapping, Optional, Tuple

import psycopg
import psycopg.errors
import psycopg.sql

from twisted.enterprise.adbapi import Connection as TxConnection

from synapse.storage.engines import PostgresEngine
from synapse.storage.engines._base import IsolationLevel

logger = logging.getLogger(__name__)


class PsycopgEngine(
    # mypy doesn't seem to like that the psycopg Connection and Cursor are Generics.
    PostgresEngine[  # type: ignore[type-var]
        psycopg.Connection[Tuple], psycopg.Cursor[Tuple], psycopg.IsolationLevel
    ]
):
    def __init__(self, database_config: Mapping[str, Any]):
        super().__init__(psycopg, database_config)  # type: ignore[arg-type]
        # psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)

        # Disables passing `bytes` to txn.execute, c.f. #6186. If you do
        # actually want to use bytes than wrap it in `bytearray`.
        # def _disable_bytes_adapter(_: bytes) -> NoReturn:
        #     raise Exception("Passing bytes to DB is disabled.")

        self.isolation_level_map = {
            IsolationLevel.READ_COMMITTED: psycopg.IsolationLevel.READ_COMMITTED,
            IsolationLevel.REPEATABLE_READ: psycopg.IsolationLevel.REPEATABLE_READ,
            IsolationLevel.SERIALIZABLE: psycopg.IsolationLevel.SERIALIZABLE,
        }
        self.default_isolation_level = psycopg.IsolationLevel.REPEATABLE_READ

    def get_server_version(self, db_conn: psycopg.Connection) -> int:
        return db_conn.info.server_version

    def set_statement_timeout(
        self, cursor: psycopg.Cursor, statement_timeout: int
    ) -> None:
        """Configure the current cursor's statement timeout."""
        cursor.execute(
            psycopg.sql.SQL("SET statement_timeout TO {}").format(statement_timeout)
        )

    def convert_param_style(self, sql: str) -> str:
        # if isinstance(sql, psycopg.sql.Composed):
        #     return sql

        return sql.replace("?", "%s")

    def is_deadlock(self, error: Exception) -> bool:
        if isinstance(error, psycopg.errors.Error):
            # https://www.postgresql.org/docs/current/static/errcodes-appendix.html
            # "40001" serialization_failure
            # "40P01" deadlock_detected
            return error.sqlstate in ["40001", "40P01"]
        return False

    def in_transaction(self, conn: psycopg.Connection) -> bool:
        return conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE

    def attempt_to_set_autocommit(
        self, conn: psycopg.Connection, autocommit: bool
    ) -> None:
        # Sometimes this gets called with a Twisted connection instead, unwrap
        # it because it doesn't support __setattr__.
        if isinstance(conn, TxConnection):
            conn = conn._connection
        conn.autocommit = autocommit

    def attempt_to_set_isolation_level(
        self, conn: psycopg.Connection, isolation_level: Optional[int]
    ) -> None:
        if isolation_level is None:
            pg_isolation_level = self.default_isolation_level
        else:
            pg_isolation_level = self.isolation_level_map[isolation_level]
        conn.isolation_level = pg_isolation_level
