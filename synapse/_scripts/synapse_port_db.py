#!/usr/bin/env python
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import argparse
import curses
import logging
import sys
import time
import traceback
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    NoReturn,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    cast,
)

import yaml
from typing_extensions import TypedDict

from twisted.internet import defer, reactor as reactor_

from synapse.config.database import DatabaseConnectionConfig
from synapse.config.homeserver import HomeServerConfig
from synapse.logging.context import (
    LoggingContext,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.storage.database import DatabasePool, LoggingTransaction, make_conn
from synapse.storage.databases.main import PushRuleStore
from synapse.storage.databases.main.account_data import AccountDataWorkerStore
from synapse.storage.databases.main.client_ips import ClientIpBackgroundUpdateStore
from synapse.storage.databases.main.deviceinbox import DeviceInboxBackgroundUpdateStore
from synapse.storage.databases.main.devices import DeviceBackgroundUpdateStore
from synapse.storage.databases.main.end_to_end_keys import EndToEndKeyBackgroundStore
from synapse.storage.databases.main.event_push_actions import EventPushActionsStore
from synapse.storage.databases.main.events_bg_updates import (
    EventsBackgroundUpdatesStore,
)
from synapse.storage.databases.main.media_repository import (
    MediaRepositoryBackgroundUpdateStore,
)
from synapse.storage.databases.main.presence import PresenceBackgroundUpdateStore
from synapse.storage.databases.main.pusher import PusherWorkerStore
from synapse.storage.databases.main.receipts import ReceiptsBackgroundUpdateStore
from synapse.storage.databases.main.registration import (
    RegistrationBackgroundUpdateStore,
    find_max_generated_user_id_localpart,
)
from synapse.storage.databases.main.room import RoomBackgroundUpdateStore
from synapse.storage.databases.main.roommember import RoomMemberBackgroundUpdateStore
from synapse.storage.databases.main.search import SearchBackgroundUpdateStore
from synapse.storage.databases.main.state import MainStateBackgroundUpdateStore
from synapse.storage.databases.main.stats import StatsStore
from synapse.storage.databases.main.user_directory import (
    UserDirectoryBackgroundUpdateStore,
)
from synapse.storage.databases.state.bg_updates import StateBackgroundUpdateStore
from synapse.storage.engines import create_engine
from synapse.storage.prepare_database import prepare_database
from synapse.types import ISynapseReactor
from synapse.util import SYNAPSE_VERSION, Clock

# Cast safety: Twisted does some naughty magic which replaces the
# twisted.internet.reactor module with a Reactor instance at runtime.
reactor = cast(ISynapseReactor, reactor_)
logger = logging.getLogger("synapse_port_db")


BOOLEAN_COLUMNS = {
    "events": ["processed", "outlier", "contains_url"],
    "rooms": ["is_public", "has_auth_chain_index"],
    "event_edges": ["is_state"],
    "presence_list": ["accepted"],
    "presence_stream": ["currently_active"],
    "public_room_list_stream": ["visibility"],
    "devices": ["hidden"],
    "device_lists_outbound_pokes": ["sent"],
    "users_who_share_rooms": ["share_private"],
    "e2e_room_keys": ["is_verified"],
    "account_validity": ["email_sent"],
    "redactions": ["have_censored"],
    "room_stats_state": ["is_federatable"],
    "local_media_repository": ["safe_from_quarantine"],
    "users": ["shadow_banned", "approved"],
    "e2e_fallback_keys_json": ["used"],
    "access_tokens": ["used"],
    "device_lists_changes_in_room": ["converted_to_destinations"],
    "pushers": ["enabled"],
}


APPEND_ONLY_TABLES = [
    "event_reference_hashes",
    "events",
    "event_json",
    "state_events",
    "room_memberships",
    "topics",
    "room_names",
    "rooms",
    "local_media_repository",
    "local_media_repository_thumbnails",
    "remote_media_cache",
    "remote_media_cache_thumbnails",
    "redactions",
    "event_edges",
    "event_auth",
    "received_transactions",
    "sent_transactions",
    "transaction_id_to_pdu",
    "users",
    "state_groups",
    "state_groups_state",
    "event_to_state_groups",
    "rejections",
    "event_search",
    "presence_stream",
    "push_rules_stream",
    "ex_outlier_stream",
    "cache_invalidation_stream_by_instance",
    "public_room_list_stream",
    "state_group_edges",
    "stream_ordering_to_exterm",
]


IGNORED_TABLES = {
    # We don't port these tables, as they're a faff and we can regenerate
    # them anyway.
    "user_directory",
    "user_directory_search",
    "user_directory_search_content",
    "user_directory_search_docsize",
    "user_directory_search_segdir",
    "user_directory_search_segments",
    "user_directory_search_stat",
    "user_directory_search_pos",
    "users_who_share_private_rooms",
    "users_in_public_room",
    # UI auth sessions have foreign keys so additional care needs to be taken,
    # the sessions are transient anyway, so ignore them.
    "ui_auth_sessions",
    "ui_auth_sessions_credentials",
    "ui_auth_sessions_ips",
}


# Error returned by the run function. Used at the top-level part of the script to
# handle errors and return codes.
end_error: Optional[str] = None
# The exec_info for the error, if any. If error is defined but not exec_info the script
# will show only the error message without the stacktrace, if exec_info is defined but
# not the error then the script will show nothing outside of what's printed in the run
# function. If both are defined, the script will print both the error and the stacktrace.
end_error_exec_info: Optional[
    Tuple[Type[BaseException], BaseException, TracebackType]
] = None

R = TypeVar("R")


class Store(
    EventPushActionsStore,
    ClientIpBackgroundUpdateStore,
    DeviceInboxBackgroundUpdateStore,
    DeviceBackgroundUpdateStore,
    EventsBackgroundUpdatesStore,
    MediaRepositoryBackgroundUpdateStore,
    RegistrationBackgroundUpdateStore,
    RoomBackgroundUpdateStore,
    RoomMemberBackgroundUpdateStore,
    SearchBackgroundUpdateStore,
    StateBackgroundUpdateStore,
    MainStateBackgroundUpdateStore,
    UserDirectoryBackgroundUpdateStore,
    EndToEndKeyBackgroundStore,
    StatsStore,
    AccountDataWorkerStore,
    PushRuleStore,
    PusherWorkerStore,
    PresenceBackgroundUpdateStore,
    ReceiptsBackgroundUpdateStore,
):
    def execute(self, f: Callable[..., R], *args: Any, **kwargs: Any) -> Awaitable[R]:
        return self.db_pool.runInteraction(f.__name__, f, *args, **kwargs)

    def execute_sql(self, sql: str, *args: object) -> Awaitable[List[Tuple]]:
        def r(txn: LoggingTransaction) -> List[Tuple]:
            txn.execute(sql, args)
            return txn.fetchall()

        return self.db_pool.runInteraction("execute_sql", r)

    def insert_many_txn(
        self, txn: LoggingTransaction, table: str, headers: List[str], rows: List[Tuple]
    ) -> None:
        sql = "INSERT INTO %s (%s) VALUES (%s)" % (
            table,
            ", ".join(k for k in headers),
            ", ".join("%s" for _ in headers),
        )

        try:
            txn.executemany(sql, rows)
        except Exception:
            logger.exception("Failed to insert: %s", table)
            raise

    # Note: the parent method is an `async def`.
    def set_room_is_public(self, room_id: str, is_public: bool) -> NoReturn:
        raise Exception(
            "Attempt to set room_is_public during port_db: database not empty?"
        )


class MockHomeserver:
    def __init__(self, config: HomeServerConfig):
        self.clock = Clock(reactor)
        self.config = config
        self.hostname = config.server.server_name
        self.version_string = SYNAPSE_VERSION

    def get_clock(self) -> Clock:
        return self.clock

    def get_reactor(self) -> ISynapseReactor:
        return reactor

    def get_instance_name(self) -> str:
        return "master"

    def should_send_federation(self) -> bool:
        return False


class Porter:
    def __init__(
        self,
        sqlite_config: Dict[str, Any],
        progress: "Progress",
        batch_size: int,
        hs_config: HomeServerConfig,
    ):
        self.sqlite_config = sqlite_config
        self.progress = progress
        self.batch_size = batch_size
        self.hs_config = hs_config

    async def setup_table(self, table: str) -> Tuple[str, int, int, int, int]:
        if table in APPEND_ONLY_TABLES:
            # It's safe to just carry on inserting.
            row = await self.postgres_store.db_pool.simple_select_one(
                table="port_from_sqlite3",
                keyvalues={"table_name": table},
                retcols=("forward_rowid", "backward_rowid"),
                allow_none=True,
            )

            total_to_port = None
            if row is None:
                if table == "sent_transactions":
                    (
                        forward_chunk,
                        already_ported,
                        total_to_port,
                    ) = await self._setup_sent_transactions()
                    backward_chunk = 0
                else:
                    await self.postgres_store.db_pool.simple_insert(
                        table="port_from_sqlite3",
                        values={
                            "table_name": table,
                            "forward_rowid": 1,
                            "backward_rowid": 0,
                        },
                    )

                    forward_chunk = 1
                    backward_chunk = 0
                    already_ported = 0
            else:
                forward_chunk = row["forward_rowid"]
                backward_chunk = row["backward_rowid"]

            if total_to_port is None:
                already_ported, total_to_port = await self._get_total_count_to_port(
                    table, forward_chunk, backward_chunk
                )
        else:

            def delete_all(txn: LoggingTransaction) -> None:
                txn.execute(
                    "DELETE FROM port_from_sqlite3 WHERE table_name = %s", (table,)
                )
                txn.execute("TRUNCATE %s CASCADE" % (table,))

            await self.postgres_store.execute(delete_all)

            await self.postgres_store.db_pool.simple_insert(
                table="port_from_sqlite3",
                values={"table_name": table, "forward_rowid": 1, "backward_rowid": 0},
            )

            forward_chunk = 1
            backward_chunk = 0

            already_ported, total_to_port = await self._get_total_count_to_port(
                table, forward_chunk, backward_chunk
            )

        return table, already_ported, total_to_port, forward_chunk, backward_chunk

    async def get_table_constraints(self) -> Dict[str, Set[str]]:
        """Returns a map of tables that have foreign key constraints to tables they depend on."""

        def _get_constraints(txn: LoggingTransaction) -> Dict[str, Set[str]]:
            # We can pull the information about foreign key constraints out from
            # the postgres schema tables.
            sql = """
                SELECT DISTINCT
                    tc.table_name,
                    ccu.table_name AS foreign_table_name
                FROM
                    information_schema.table_constraints AS tc
                    INNER JOIN information_schema.constraint_column_usage AS ccu
                    USING (table_schema, constraint_name)
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  AND tc.table_name != ccu.table_name;
            """
            txn.execute(sql)

            results: Dict[str, Set[str]] = {}
            for table, foreign_table in txn:
                results.setdefault(table, set()).add(foreign_table)
            return results

        return await self.postgres_store.db_pool.runInteraction(
            "get_table_constraints", _get_constraints
        )

    async def handle_table(
        self,
        table: str,
        postgres_size: int,
        table_size: int,
        forward_chunk: int,
        backward_chunk: int,
    ) -> None:
        logger.info(
            "Table %s: %i/%i (rows %i-%i) already ported",
            table,
            postgres_size,
            table_size,
            backward_chunk + 1,
            forward_chunk - 1,
        )

        if not table_size:
            return

        self.progress.add_table(table, postgres_size, table_size)

        if table == "event_search":
            await self.handle_search_table(
                postgres_size, table_size, forward_chunk, backward_chunk
            )
            return

        if table in IGNORED_TABLES:
            self.progress.update(table, table_size)  # Mark table as done
            return

        if table == "user_directory_stream_pos":
            # We need to make sure there is a single row, `(X, null), as that is
            # what synapse expects to be there.
            await self.postgres_store.db_pool.simple_insert(
                table=table, values={"stream_id": None}
            )
            self.progress.update(table, table_size)  # Mark table as done
            return

        # We sweep over rowids in two directions: one forwards (rowids 1, 2, 3, ...)
        # and another backwards (rowids 0, -1, -2, ...).
        forward_select = (
            "SELECT rowid, * FROM %s WHERE rowid >= ? ORDER BY rowid LIMIT ?" % (table,)
        )

        backward_select = (
            "SELECT rowid, * FROM %s WHERE rowid <= ? ORDER BY rowid DESC LIMIT ?"
            % (table,)
        )

        do_forward = [True]
        do_backward = [True]

        while True:

            def r(
                txn: LoggingTransaction,
            ) -> Tuple[Optional[List[str]], List[Tuple], List[Tuple]]:
                forward_rows = []
                backward_rows = []
                if do_forward[0]:
                    txn.execute(forward_select, (forward_chunk, self.batch_size))
                    forward_rows = txn.fetchall()
                    if not forward_rows:
                        do_forward[0] = False

                if do_backward[0]:
                    txn.execute(backward_select, (backward_chunk, self.batch_size))
                    backward_rows = txn.fetchall()
                    if not backward_rows:
                        do_backward[0] = False

                if forward_rows or backward_rows:
                    headers = [column[0] for column in txn.description]
                else:
                    headers = None

                return headers, forward_rows, backward_rows

            headers, frows, brows = await self.sqlite_store.db_pool.runInteraction(
                "select", r
            )

            if frows or brows:
                assert headers is not None
                if frows:
                    forward_chunk = max(row[0] for row in frows) + 1
                if brows:
                    backward_chunk = min(row[0] for row in brows) - 1

                rows = frows + brows
                rows = self._convert_rows(table, headers, rows)

                def insert(txn: LoggingTransaction) -> None:
                    assert headers is not None
                    self.postgres_store.insert_many_txn(txn, table, headers[1:], rows)

                    self.postgres_store.db_pool.simple_update_one_txn(
                        txn,
                        table="port_from_sqlite3",
                        keyvalues={"table_name": table},
                        updatevalues={
                            "forward_rowid": forward_chunk,
                            "backward_rowid": backward_chunk,
                        },
                    )

                await self.postgres_store.execute(insert)

                postgres_size += len(rows)

                self.progress.update(table, postgres_size)
            else:
                return

    async def handle_search_table(
        self,
        postgres_size: int,
        table_size: int,
        forward_chunk: int,
        backward_chunk: int,
    ) -> None:
        select = (
            "SELECT es.rowid, es.*, e.origin_server_ts, e.stream_ordering"
            " FROM event_search as es"
            " INNER JOIN events AS e USING (event_id, room_id)"
            " WHERE es.rowid >= ?"
            " ORDER BY es.rowid LIMIT ?"
        )

        while True:

            def r(txn: LoggingTransaction) -> Tuple[List[str], List[Tuple]]:
                txn.execute(select, (forward_chunk, self.batch_size))
                rows = txn.fetchall()
                headers = [column[0] for column in txn.description]

                return headers, rows

            headers, rows = await self.sqlite_store.db_pool.runInteraction("select", r)

            if rows:
                forward_chunk = rows[-1][0] + 1

                # We have to treat event_search differently since it has a
                # different structure in the two different databases.
                def insert(txn: LoggingTransaction) -> None:
                    sql = (
                        "INSERT INTO event_search (event_id, room_id, key,"
                        " sender, vector, origin_server_ts, stream_ordering)"
                        " VALUES (?,?,?,?,to_tsvector('english', ?),?,?)"
                    )

                    rows_dict = []
                    for row in rows:
                        d = dict(zip(headers, row))
                        if "\0" in d["value"]:
                            logger.warning("dropping search row %s", d)
                        else:
                            rows_dict.append(d)

                    txn.executemany(
                        sql,
                        [
                            (
                                row["event_id"],
                                row["room_id"],
                                row["key"],
                                row["sender"],
                                row["value"],
                                row["origin_server_ts"],
                                row["stream_ordering"],
                            )
                            for row in rows_dict
                        ],
                    )

                    self.postgres_store.db_pool.simple_update_one_txn(
                        txn,
                        table="port_from_sqlite3",
                        keyvalues={"table_name": "event_search"},
                        updatevalues={
                            "forward_rowid": forward_chunk,
                            "backward_rowid": backward_chunk,
                        },
                    )

                await self.postgres_store.execute(insert)

                postgres_size += len(rows)

                self.progress.update("event_search", postgres_size)

            else:
                return

    def build_db_store(
        self,
        db_config: DatabaseConnectionConfig,
        allow_outdated_version: bool = False,
    ) -> Store:
        """Builds and returns a database store using the provided configuration.

        Args:
            db_config: The database configuration
            allow_outdated_version: True to suppress errors about the database server
                version being too old to run a complete synapse

        Returns:
            The built Store object.
        """
        self.progress.set_state("Preparing %s" % db_config.config["name"])

        engine = create_engine(db_config.config)

        hs = MockHomeserver(self.hs_config)

        with make_conn(db_config, engine, "portdb") as db_conn:
            engine.check_database(
                db_conn, allow_outdated_version=allow_outdated_version
            )
            prepare_database(db_conn, engine, config=self.hs_config)
            # Type safety: ignore that we're using Mock homeservers here.
            store = Store(DatabasePool(hs, db_config, engine), db_conn, hs)  # type: ignore[arg-type]
            db_conn.commit()

        return store

    async def run_background_updates_on_postgres(self) -> None:
        # Manually apply all background updates on the PostgreSQL database.
        postgres_ready = (
            await self.postgres_store.db_pool.updates.has_completed_background_updates()
        )

        if not postgres_ready:
            # Only say that we're running background updates when there are background
            # updates to run.
            self.progress.set_state("Running background updates on PostgreSQL")

        while not postgres_ready:
            await self.postgres_store.db_pool.updates.do_next_background_update(True)
            postgres_ready = await (
                self.postgres_store.db_pool.updates.has_completed_background_updates()
            )

    @staticmethod
    def _is_sqlite_autovacuum_enabled(txn: LoggingTransaction) -> bool:
        """
        Returns true if auto_vacuum is enabled in SQLite.
        https://www.sqlite.org/pragma.html#pragma_auto_vacuum

        Vacuuming changes the rowids on rows in the database.
        Auto-vacuuming is therefore dangerous when used in conjunction with this script.

        Note that the auto_vacuum setting can't be changed without performing
        a VACUUM after trying to change the pragma.
        """
        txn.execute("PRAGMA auto_vacuum")
        row = txn.fetchone()
        assert row is not None, "`PRAGMA auto_vacuum` did not give a row."
        (autovacuum_setting,) = row
        # 0 means off. 1 means full. 2 means incremental.
        return autovacuum_setting != 0

    async def run(self) -> None:
        """Ports the SQLite database to a PostgreSQL database.

        When a fatal error is met, its message is assigned to the global "end_error"
        variable. When this error comes with a stacktrace, its exec_info is assigned to
        the global "end_error_exec_info" variable.
        """
        global end_error

        try:
            # we allow people to port away from outdated versions of sqlite.
            self.sqlite_store = self.build_db_store(
                DatabaseConnectionConfig("master-sqlite", self.sqlite_config),
                allow_outdated_version=True,
            )

            # For safety, ensure auto_vacuums are disabled.
            if await self.sqlite_store.db_pool.runInteraction(
                "is_sqlite_autovacuum_enabled", self._is_sqlite_autovacuum_enabled
            ):
                end_error = (
                    "auto_vacuum is enabled in the SQLite database."
                    " (This is not the default configuration.)\n"
                    " This script relies on rowids being consistent and must not"
                    " be used if the database could be vacuumed between re-runs.\n"
                    " To disable auto_vacuum, you need to stop Synapse and run the following SQL:\n"
                    " PRAGMA auto_vacuum=off;\n"
                    " VACUUM;"
                )
                return

            # Check if all background updates are done, abort if not.
            updates_complete = (
                await self.sqlite_store.db_pool.updates.has_completed_background_updates()
            )
            if not updates_complete:
                end_error = (
                    "Pending background updates exist in the SQLite3 database."
                    " Please start Synapse again and wait until every update has finished"
                    " before running this script.\n"
                )
                return

            self.postgres_store = self.build_db_store(
                self.hs_config.database.get_single_database()
            )

            await self.run_background_updates_on_postgres()

            self.progress.set_state("Creating port tables")

            def create_port_table(txn: LoggingTransaction) -> None:
                txn.execute(
                    "CREATE TABLE IF NOT EXISTS port_from_sqlite3 ("
                    " table_name varchar(100) NOT NULL UNIQUE,"
                    " forward_rowid bigint NOT NULL,"
                    " backward_rowid bigint NOT NULL"
                    ")"
                )

            # The old port script created a table with just a "rowid" column.
            # We want people to be able to rerun this script from an old port
            # so that they can pick up any missing events that were not
            # ported across.
            def alter_table(txn: LoggingTransaction) -> None:
                txn.execute(
                    "ALTER TABLE IF EXISTS port_from_sqlite3"
                    " RENAME rowid TO forward_rowid"
                )
                txn.execute(
                    "ALTER TABLE IF EXISTS port_from_sqlite3"
                    " ADD backward_rowid bigint NOT NULL DEFAULT 0"
                )

            try:
                await self.postgres_store.db_pool.runInteraction(
                    "alter_table", alter_table
                )
            except Exception:
                # On Error Resume Next
                pass

            await self.postgres_store.db_pool.runInteraction(
                "create_port_table", create_port_table
            )

            # Step 2. Set up sequences
            #
            # We do this before porting the tables so that event if we fail half
            # way through the postgres DB always have sequences that are greater
            # than their respective tables. If we don't then creating the
            # `DataStore` object will fail due to the inconsistency.
            self.progress.set_state("Setting up sequence generators")
            await self._setup_state_group_id_seq()
            await self._setup_user_id_seq()
            await self._setup_events_stream_seqs()
            await self._setup_sequence(
                "device_inbox_sequence", ("device_inbox", "device_federation_outbox")
            )
            await self._setup_sequence(
                "account_data_sequence",
                ("room_account_data", "room_tags_revisions", "account_data"),
            )
            await self._setup_sequence("receipts_sequence", ("receipts_linearized",))
            await self._setup_sequence("presence_stream_sequence", ("presence_stream",))
            await self._setup_auth_chain_sequence()

            # Step 3. Get tables.
            self.progress.set_state("Fetching tables")
            sqlite_tables = await self.sqlite_store.db_pool.simple_select_onecol(
                table="sqlite_master", keyvalues={"type": "table"}, retcol="name"
            )

            postgres_tables = await self.postgres_store.db_pool.simple_select_onecol(
                table="information_schema.tables",
                keyvalues={},
                retcol="distinct table_name",
            )

            tables = set(sqlite_tables) & set(postgres_tables)
            logger.info("Found %d tables", len(tables))

            # Step 4. Figure out what still needs copying
            self.progress.set_state("Checking on port progress")
            setup_res = await make_deferred_yieldable(
                defer.gatherResults(
                    [
                        run_in_background(self.setup_table, table)
                        for table in tables
                        if table not in ["schema_version", "applied_schema_deltas"]
                        and not table.startswith("sqlite_")
                    ],
                    consumeErrors=True,
                )
            )
            # Map from table name to args passed to `handle_table`, i.e. a tuple
            # of: `postgres_size`, `table_size`, `forward_chunk`, `backward_chunk`.
            tables_to_port_info_map = {r[0]: r[1:] for r in setup_res}

            # Step 5. Do the copying.
            #
            # This is slightly convoluted as we need to ensure tables are ported
            # in the correct order due to foreign key constraints.
            self.progress.set_state("Copying to postgres")

            constraints = await self.get_table_constraints()
            tables_ported = set()  # type: Set[str]

            while tables_to_port_info_map:
                # Pulls out all tables that are still to be ported and which
                # only depend on tables that are already ported (if any).
                tables_to_port = [
                    table
                    for table in tables_to_port_info_map
                    if not constraints.get(table, set()) - tables_ported
                ]

                await make_deferred_yieldable(
                    defer.gatherResults(
                        [
                            run_in_background(
                                self.handle_table,
                                table,
                                *tables_to_port_info_map.pop(table),
                            )
                            for table in tables_to_port
                        ],
                        consumeErrors=True,
                    )
                )

                tables_ported.update(tables_to_port)

            self.progress.done()
        except Exception as e:
            global end_error_exec_info
            end_error = str(e)
            # Type safety: we're in an exception handler, so the exc_info() tuple
            # will not be (None, None, None).
            end_error_exec_info = sys.exc_info()  # type: ignore[assignment]
            logger.exception("")
        finally:
            reactor.stop()

    def _convert_rows(
        self, table: str, headers: List[str], rows: List[Tuple]
    ) -> List[Tuple]:
        bool_col_names = BOOLEAN_COLUMNS.get(table, [])

        bool_cols = [i for i, h in enumerate(headers) if h in bool_col_names]

        class BadValueException(Exception):
            pass

        def conv(j: int, col: object) -> object:
            if j in bool_cols:
                return bool(col)
            if isinstance(col, bytes):
                return bytearray(col)
            elif isinstance(col, str) and "\0" in col:
                logger.warning(
                    "DROPPING ROW: NUL value in table %s col %s: %r",
                    table,
                    headers[j],
                    col,
                )
                raise BadValueException()
            return col

        outrows = []
        for row in rows:
            try:
                outrows.append(
                    tuple(conv(j, col) for j, col in enumerate(row) if j > 0)
                )
            except BadValueException:
                pass

        return outrows

    async def _setup_sent_transactions(self) -> Tuple[int, int, int]:
        # Only save things from the last day
        yesterday = int(time.time() * 1000) - 86400000

        # And save the max transaction id from each destination
        select = (
            "SELECT rowid, * FROM sent_transactions WHERE rowid IN ("
            "SELECT max(rowid) FROM sent_transactions"
            " GROUP BY destination"
            ")"
        )

        def r(txn: LoggingTransaction) -> Tuple[List[str], List[Tuple]]:
            txn.execute(select)
            rows = txn.fetchall()
            headers: List[str] = [column[0] for column in txn.description]

            ts_ind = headers.index("ts")

            return headers, [r for r in rows if r[ts_ind] < yesterday]

        headers, rows = await self.sqlite_store.db_pool.runInteraction("select", r)

        rows = self._convert_rows("sent_transactions", headers, rows)

        inserted_rows = len(rows)
        if inserted_rows:
            max_inserted_rowid = max(r[0] for r in rows)

            def insert(txn: LoggingTransaction) -> None:
                self.postgres_store.insert_many_txn(
                    txn, "sent_transactions", headers[1:], rows
                )

            await self.postgres_store.execute(insert)
        else:
            max_inserted_rowid = 0

        def get_start_id(txn: LoggingTransaction) -> int:
            txn.execute(
                "SELECT rowid FROM sent_transactions WHERE ts >= ?"
                " ORDER BY rowid ASC LIMIT 1",
                (yesterday,),
            )

            rows = txn.fetchall()
            if rows:
                return rows[0][0]
            else:
                return 1

        next_chunk = await self.sqlite_store.execute(get_start_id)
        next_chunk = max(max_inserted_rowid + 1, next_chunk)

        await self.postgres_store.db_pool.simple_insert(
            table="port_from_sqlite3",
            values={
                "table_name": "sent_transactions",
                "forward_rowid": next_chunk,
                "backward_rowid": 0,
            },
        )

        def get_sent_table_size(txn: LoggingTransaction) -> int:
            txn.execute(
                "SELECT count(*) FROM sent_transactions" " WHERE ts >= ?", (yesterday,)
            )
            result = txn.fetchone()
            assert result is not None
            return int(result[0])

        remaining_count = await self.sqlite_store.execute(get_sent_table_size)

        total_count = remaining_count + inserted_rows

        return next_chunk, inserted_rows, total_count

    async def _get_remaining_count_to_port(
        self, table: str, forward_chunk: int, backward_chunk: int
    ) -> int:
        frows = cast(
            List[Tuple[int]],
            await self.sqlite_store.execute_sql(
                "SELECT count(*) FROM %s WHERE rowid >= ?" % (table,), forward_chunk
            ),
        )

        brows = cast(
            List[Tuple[int]],
            await self.sqlite_store.execute_sql(
                "SELECT count(*) FROM %s WHERE rowid <= ?" % (table,), backward_chunk
            ),
        )

        return frows[0][0] + brows[0][0]

    async def _get_already_ported_count(self, table: str) -> int:
        rows = await self.postgres_store.execute_sql(
            "SELECT count(*) FROM %s" % (table,)
        )

        return rows[0][0]

    async def _get_total_count_to_port(
        self, table: str, forward_chunk: int, backward_chunk: int
    ) -> Tuple[int, int]:
        remaining, done = await make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self._get_remaining_count_to_port,
                        table,
                        forward_chunk,
                        backward_chunk,
                    ),
                    run_in_background(self._get_already_ported_count, table),
                ],
            )
        )

        remaining = int(remaining) if remaining else 0
        done = int(done) if done else 0

        return done, remaining + done

    async def _setup_state_group_id_seq(self) -> None:
        curr_id: Optional[
            int
        ] = await self.sqlite_store.db_pool.simple_select_one_onecol(
            table="state_groups", keyvalues={}, retcol="MAX(id)", allow_none=True
        )

        if not curr_id:
            return

        def r(txn: LoggingTransaction) -> None:
            assert curr_id is not None
            next_id = curr_id + 1
            txn.execute("ALTER SEQUENCE state_group_id_seq RESTART WITH %s", (next_id,))

        await self.postgres_store.db_pool.runInteraction("setup_state_group_id_seq", r)

    async def _setup_user_id_seq(self) -> None:
        curr_id = await self.sqlite_store.db_pool.runInteraction(
            "setup_user_id_seq", find_max_generated_user_id_localpart
        )

        def r(txn: LoggingTransaction) -> None:
            next_id = curr_id + 1
            txn.execute("ALTER SEQUENCE user_id_seq RESTART WITH %s", (next_id,))

        await self.postgres_store.db_pool.runInteraction("setup_user_id_seq", r)

    async def _setup_events_stream_seqs(self) -> None:
        """Set the event stream sequences to the correct values."""

        # We get called before we've ported the events table, so we need to
        # fetch the current positions from the SQLite store.
        curr_forward_id = await self.sqlite_store.db_pool.simple_select_one_onecol(
            table="events", keyvalues={}, retcol="MAX(stream_ordering)", allow_none=True
        )

        curr_backward_id = await self.sqlite_store.db_pool.simple_select_one_onecol(
            table="events",
            keyvalues={},
            retcol="MAX(-MIN(stream_ordering), 1)",
            allow_none=True,
        )

        def _setup_events_stream_seqs_set_pos(txn: LoggingTransaction) -> None:
            if curr_forward_id:
                txn.execute(
                    "ALTER SEQUENCE events_stream_seq RESTART WITH %s",
                    (curr_forward_id + 1,),
                )

            if curr_backward_id:
                txn.execute(
                    "ALTER SEQUENCE events_backfill_stream_seq RESTART WITH %s",
                    (curr_backward_id + 1,),
                )

        await self.postgres_store.db_pool.runInteraction(
            "_setup_events_stream_seqs",
            _setup_events_stream_seqs_set_pos,
        )

    async def _setup_sequence(
        self, sequence_name: str, stream_id_tables: Iterable[str]
    ) -> None:
        """Set a sequence to the correct value."""
        current_stream_ids = []
        for stream_id_table in stream_id_tables:
            max_stream_id = cast(
                int,
                await self.sqlite_store.db_pool.simple_select_one_onecol(
                    table=stream_id_table,
                    keyvalues={},
                    retcol="COALESCE(MAX(stream_id), 1)",
                    allow_none=True,
                ),
            )
            current_stream_ids.append(max_stream_id)

        next_id = max(current_stream_ids) + 1

        def r(txn: LoggingTransaction) -> None:
            sql = "ALTER SEQUENCE %s RESTART WITH" % (sequence_name,)
            txn.execute(sql + " %s", (next_id,))

        await self.postgres_store.db_pool.runInteraction(
            "_setup_%s" % (sequence_name,), r
        )

    async def _setup_auth_chain_sequence(self) -> None:
        curr_chain_id: Optional[
            int
        ] = await self.sqlite_store.db_pool.simple_select_one_onecol(
            table="event_auth_chains",
            keyvalues={},
            retcol="MAX(chain_id)",
            allow_none=True,
        )

        def r(txn: LoggingTransaction) -> None:
            # Presumably there is at least one row in event_auth_chains.
            assert curr_chain_id is not None
            txn.execute(
                "ALTER SEQUENCE event_auth_chain_id RESTART WITH %s",
                (curr_chain_id + 1,),
            )

        if curr_chain_id is not None:
            await self.postgres_store.db_pool.runInteraction(
                "_setup_event_auth_chain_id",
                r,
            )


##############################################
# The following is simply UI stuff
##############################################


class TableProgress(TypedDict):
    start: int
    num_done: int
    total: int
    perc: int


class Progress:
    """Used to report progress of the port"""

    def __init__(self) -> None:
        self.tables: Dict[str, TableProgress] = {}

        self.start_time = int(time.time())

    def add_table(self, table: str, cur: int, size: int) -> None:
        self.tables[table] = {
            "start": cur,
            "num_done": cur,
            "total": size,
            "perc": int(cur * 100 / size),
        }

    def update(self, table: str, num_done: int) -> None:
        data = self.tables[table]
        data["num_done"] = num_done
        data["perc"] = int(num_done * 100 / data["total"])

    def done(self) -> None:
        pass

    def set_state(self, state: str) -> None:
        pass


class CursesProgress(Progress):
    """Reports progress to a curses window"""

    def __init__(self, stdscr: "curses.window"):
        self.stdscr = stdscr

        curses.use_default_colors()
        curses.curs_set(0)

        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)

        self.last_update = 0.0

        self.finished = False

        self.total_processed = 0
        self.total_remaining = 0

        super(CursesProgress, self).__init__()

    def update(self, table: str, num_done: int) -> None:
        super(CursesProgress, self).update(table, num_done)

        self.total_processed = 0
        self.total_remaining = 0
        for data in self.tables.values():
            self.total_processed += data["num_done"] - data["start"]
            self.total_remaining += data["total"] - data["num_done"]

        self.render()

    def render(self, force: bool = False) -> None:
        now = time.time()

        if not force and now - self.last_update < 0.2:
            # reactor.callLater(1, self.render)
            return

        self.stdscr.clear()

        rows, cols = self.stdscr.getmaxyx()

        duration = int(now) - int(self.start_time)

        minutes, seconds = divmod(duration, 60)
        duration_str = "%02dm %02ds" % (minutes, seconds)

        if self.finished:
            status = "Time spent: %s (Done!)" % (duration_str,)
        else:

            if self.total_processed > 0:
                left = float(self.total_remaining) / self.total_processed

                est_remaining = (int(now) - self.start_time) * left
                est_remaining_str = "%02dm %02ds remaining" % divmod(est_remaining, 60)
            else:
                est_remaining_str = "Unknown"
            status = "Time spent: %s (est. remaining: %s)" % (
                duration_str,
                est_remaining_str,
            )

        self.stdscr.addstr(0, 0, status, curses.A_BOLD)

        max_len = max(len(t) for t in self.tables.keys())

        left_margin = 5
        middle_space = 1

        items = sorted(self.tables.items(), key=lambda i: (i[1]["perc"], i[0]))

        for i, (table, data) in enumerate(items):
            if i + 2 >= rows:
                break

            perc = data["perc"]

            color = curses.color_pair(2) if perc == 100 else curses.color_pair(1)

            self.stdscr.addstr(
                i + 2, left_margin + max_len - len(table), table, curses.A_BOLD | color
            )

            size = 20

            progress = "[%s%s]" % (
                "#" * int(perc * size / 100),
                " " * (size - int(perc * size / 100)),
            )

            self.stdscr.addstr(
                i + 2,
                left_margin + max_len + middle_space,
                "%s %3d%% (%d/%d)" % (progress, perc, data["num_done"], data["total"]),
            )

        if self.finished:
            self.stdscr.addstr(rows - 1, 0, "Press any key to exit...")

        self.stdscr.refresh()
        self.last_update = time.time()

    def done(self) -> None:
        self.finished = True
        self.render(True)
        self.stdscr.getch()

    def set_state(self, state: str) -> None:
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, state + "...", curses.A_BOLD)
        self.stdscr.refresh()


class TerminalProgress(Progress):
    """Just prints progress to the terminal"""

    def update(self, table: str, num_done: int) -> None:
        super(TerminalProgress, self).update(table, num_done)

        data = self.tables[table]

        print(
            "%s: %d%% (%d/%d)" % (table, data["perc"], data["num_done"], data["total"])
        )

    def set_state(self, state: str) -> None:
        print(state + "...")


##############################################
##############################################


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A script to port an existing synapse SQLite database to"
        " a new PostgreSQL database."
    )
    parser.add_argument("-v", action="store_true")
    parser.add_argument(
        "--sqlite-database",
        required=True,
        help="The snapshot of the SQLite database file. This must not be"
        " currently used by a running synapse server",
    )
    parser.add_argument(
        "--postgres-config",
        type=argparse.FileType("r"),
        required=True,
        help="The database config file for the PostgreSQL database",
    )
    parser.add_argument(
        "--curses", action="store_true", help="display a curses based progress UI"
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="The number of rows to select from the SQLite table each"
        " iteration [default=1000]",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.v else logging.INFO,
        format="%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s",
        filename="port-synapse.log" if args.curses else None,
    )

    sqlite_config = {
        "name": "sqlite3",
        "args": {
            "database": args.sqlite_database,
            "cp_min": 1,
            "cp_max": 1,
            "check_same_thread": False,
        },
    }

    hs_config = yaml.safe_load(args.postgres_config)

    if "database" not in hs_config:
        sys.stderr.write("The configuration file must have a 'database' section.\n")
        sys.exit(4)

    postgres_config = hs_config["database"]

    if "name" not in postgres_config:
        sys.stderr.write("Malformed database config: no 'name'\n")
        sys.exit(2)
    if postgres_config["name"] != "psycopg2":
        sys.stderr.write("Database must use the 'psycopg2' connector.\n")
        sys.exit(3)

    config = HomeServerConfig()
    config.parse_config_dict(hs_config, "", "")

    def start(stdscr: Optional["curses.window"] = None) -> None:
        progress: Progress
        if stdscr:
            progress = CursesProgress(stdscr)
        else:
            progress = TerminalProgress()

        porter = Porter(
            sqlite_config=sqlite_config,
            progress=progress,
            batch_size=args.batch_size,
            hs_config=config,
        )

        @defer.inlineCallbacks
        def run() -> Generator["defer.Deferred[Any]", Any, None]:
            with LoggingContext("synapse_port_db_run"):
                yield defer.ensureDeferred(porter.run())

        reactor.callWhenRunning(run)

        reactor.run()

    if args.curses:
        curses.wrapper(start)
    else:
        start()

    if end_error:
        if end_error_exec_info:
            exc_type, exc_value, exc_traceback = end_error_exec_info
            traceback.print_exception(exc_type, exc_value, exc_traceback)

        sys.stderr.write(end_error)

        sys.exit(5)


if __name__ == "__main__":
    main()
