# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import threading
from typing import Callable, List, Optional

from synapse.storage.database import LoggingDatabaseConnection
from synapse.storage.engines import (
    BaseDatabaseEngine,
    IncorrectDatabaseSetup,
    PostgresEngine,
)
from synapse.storage.types import Connection, Cursor

logger = logging.getLogger(__name__)


_INCONSISTENT_SEQUENCE_ERROR = """
Postgres sequence '%(seq)s' is inconsistent with associated
table '%(table)s'. This can happen if Synapse has been downgraded and
then upgraded again, or due to a bad migration.

To fix this error, shut down Synapse (including any and all workers)
and run the following SQL:

    SELECT setval('%(seq)s', (
        %(max_id_sql)s
    ));

See docs/postgres.md for more information.
"""


class SequenceGenerator(metaclass=abc.ABCMeta):
    """A class which generates a unique sequence of integers"""

    @abc.abstractmethod
    def get_next_id_txn(self, txn: Cursor) -> int:
        """Gets the next ID in the sequence"""
        ...

    @abc.abstractmethod
    def check_consistency(
        self,
        db_conn: LoggingDatabaseConnection,
        table: str,
        id_column: str,
        positive: bool = True,
    ):
        """Should be called during start up to test that the current value of
        the sequence is greater than or equal to the maximum ID in the table.

        This is to handle various cases where the sequence value can get out
        of sync with the table, e.g. if Synapse gets rolled back to a previous
        version and the rolled forwards again.
        """
        ...


class PostgresSequenceGenerator(SequenceGenerator):
    """An implementation of SequenceGenerator which uses a postgres sequence"""

    def __init__(self, sequence_name: str):
        self._sequence_name = sequence_name

    def get_next_id_txn(self, txn: Cursor) -> int:
        txn.execute("SELECT nextval(?)", (self._sequence_name,))
        return txn.fetchone()[0]

    def get_next_mult_txn(self, txn: Cursor, n: int) -> List[int]:
        txn.execute(
            "SELECT nextval(?) FROM generate_series(1, ?)", (self._sequence_name, n)
        )
        return [i for (i,) in txn]

    def check_consistency(
        self,
        db_conn: LoggingDatabaseConnection,
        table: str,
        id_column: str,
        positive: bool = True,
    ):
        txn = db_conn.cursor(txn_name="sequence.check_consistency")

        # First we get the current max ID from the table.
        table_sql = "SELECT GREATEST(%(agg)s(%(id)s), 0) FROM %(table)s" % {
            "id": id_column,
            "table": table,
            "agg": "MAX" if positive else "-MIN",
        }

        txn.execute(table_sql)
        row = txn.fetchone()
        if not row:
            # Table is empty, so nothing to do.
            txn.close()
            return

        # Now we fetch the current value from the sequence and compare with the
        # above.
        max_stream_id = row[0]
        txn.execute(
            "SELECT last_value, is_called FROM %(seq)s" % {"seq": self._sequence_name}
        )
        last_value, is_called = txn.fetchone()
        txn.close()

        # If `is_called` is False then `last_value` is actually the value that
        # will be generated next, so we decrement to get the true "last value".
        if not is_called:
            last_value -= 1

        if max_stream_id > last_value:
            logger.warning(
                "Postgres sequence %s is behind table %s: %d < %d",
                self._sequence_name,
                table,
                last_value,
                max_stream_id,
            )
            raise IncorrectDatabaseSetup(
                _INCONSISTENT_SEQUENCE_ERROR
                % {"seq": self._sequence_name, "table": table, "max_id_sql": table_sql}
            )


GetFirstCallbackType = Callable[[Cursor], int]


class LocalSequenceGenerator(SequenceGenerator):
    """An implementation of SequenceGenerator which uses local locking

    This only works reliably if there are no other worker processes generating IDs at
    the same time.
    """

    def __init__(self, get_first_callback: GetFirstCallbackType):
        """
        Args:
            get_first_callback: a callback which is called on the first call to
                 get_next_id_txn; should return the curreent maximum id
        """
        # the callback. this is cleared after it is called, so that it can be GCed.
        self._callback = get_first_callback  # type: Optional[GetFirstCallbackType]

        # The current max value, or None if we haven't looked in the DB yet.
        self._current_max_id = None  # type: Optional[int]
        self._lock = threading.Lock()

    def get_next_id_txn(self, txn: Cursor) -> int:
        # We do application locking here since if we're using sqlite then
        # we are a single process synapse.
        with self._lock:
            if self._current_max_id is None:
                assert self._callback is not None
                self._current_max_id = self._callback(txn)
                self._callback = None

            self._current_max_id += 1
            return self._current_max_id

    def check_consistency(
        self, db_conn: Connection, table: str, id_column: str, positive: bool = True
    ):
        # There is nothing to do for in memory sequences
        pass


def build_sequence_generator(
    database_engine: BaseDatabaseEngine,
    get_first_callback: GetFirstCallbackType,
    sequence_name: str,
) -> SequenceGenerator:
    """Get the best impl of SequenceGenerator available

    This uses PostgresSequenceGenerator on postgres, and a locally-locked impl on
    sqlite.

    Args:
        database_engine: the database engine we are connected to
        get_first_callback: a callback which gets the next sequence ID. Used if
            we're on sqlite.
        sequence_name: the name of a postgres sequence to use.
    """
    if isinstance(database_engine, PostgresEngine):
        return PostgresSequenceGenerator(sequence_name)
    else:
        return LocalSequenceGenerator(get_first_callback)
