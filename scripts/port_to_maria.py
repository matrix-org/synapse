# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from twisted.internet import defer, reactor
from twisted.enterprise import adbapi

from synapse.storage._base import LoggingTransaction, SQLBaseStore
from synapse.storage.engines import create_engine

import argparse
import itertools
import logging
import yaml


logger = logging.getLogger("port_to_maria")


BINARY_COLUMNS = {
    "event_content_hashes": ["hash"],
    "event_reference_hashes": ["hash"],
    "event_signatures": ["signature"],
    "event_edge_hashes": ["hash"],
    "events": ["content", "unrecognized_keys"],
    "event_json": ["internal_metadata", "json"],
    "application_services_txns": ["event_ids"],
    "received_transactions": ["response_json"],
    "sent_transactions": ["response_json"],
    "server_tls_certificates": ["tls_certificate"],
    "server_signature_keys": ["verify_key"],
    "pushers": ["pushkey", "data"],
    "user_filters": ["filter_json"],
}

UNICODE_COLUMNS = {
    "events": ["content", "unrecognized_keys"],
    "event_json": ["internal_metadata", "json"],
    "users": ["password_hash"],
}


class Store(object):
    def __init__(self, db_pool, engine):
        self.db_pool = db_pool
        self.engine = engine

    _simple_insert_txn = SQLBaseStore.__dict__["_simple_insert_txn"]
    _simple_insert = SQLBaseStore.__dict__["_simple_insert"]

    _simple_select_onecol_txn = SQLBaseStore.__dict__["_simple_select_onecol_txn"]
    _simple_select_onecol = SQLBaseStore.__dict__["_simple_select_onecol"]

    _execute_and_decode = SQLBaseStore.__dict__["_execute_and_decode"]

    def runInteraction(self, desc, func, *args, **kwargs):
        def r(conn):
            try:
                i = 0
                N = 5
                while True:
                    try:
                        txn = conn.cursor()
                        return func(
                            LoggingTransaction(txn, desc, self.engine),
                            *args, **kwargs
                        )
                    except self.engine.module.DatabaseError as e:
                        if self.engine.is_deadlock(e):
                            logger.warn("[TXN DEADLOCK] {%s} %d/%d", desc, i, N)
                            if i < N:
                                i += 1
                                conn.rollback()
                                continue
                        raise
            except Exception as e:
                logger.debug("[TXN FAIL] {%s}", desc, e)
                raise

        return self.db_pool.runWithConnection(r)

    def insert_many(self, table, headers, rows):
        sql = "INSERT INTO %s (%s) VALUES (%s)" % (
            table,
            ", ".join(k for k in headers),
            ", ".join("%s" for _ in headers)
        )

        def t(txn):
            try:
                txn.executemany(sql, rows)
            except:
                logger.exception(
                    "Failed to insert: %s",
                    table,
                )
                raise

        return self.runInteraction("insert_many", t)


def chunks(n):
    for i in itertools.count(0, n):
        yield range(i, i+n)


@defer.inlineCallbacks
def handle_table(table, sqlite_store, mysql_store):
    N = 1000

    select = "SELECT rowid, * FROM %s WHERE rowid >= ? ORDER BY rowid LIMIT ?" % (table,)

    uni_col_names = UNICODE_COLUMNS.get(table, [])

    def conv_uni(c):
        return sqlite_store.engine.load_unicode(c)

    next_chunk = 0
    while True:
        def r(txn):
            txn.execute(select, (next_chunk, N,))
            rows = txn.fetchall()
            headers = [column[0] for column in txn.description]

            return headers, rows

        headers, rows = yield sqlite_store.runInteraction("select", r)

        logger.info("Got %d rows for %s", len(rows), table)

        if rows:
            uni_cols = [i for i, h in enumerate(headers) if h in uni_col_names]
            next_chunk = rows[-1][0] + 1

            for i, row in enumerate(rows):
                rows[i] = tuple(
                    mysql_store.engine.encode_parameter(
                        conv_uni(col) if j in uni_cols else col
                    )
                    for j, col in enumerate(row)
                    if j > 0
                )

            yield mysql_store.insert_many(table, headers[1:], rows)
        else:
            return


def setup_db(db_config, database_engine):
    db_conn = database_engine.module.connect(
        **{
            k: v for k, v in db_config.get("args", {}).items()
            if not k.startswith("cp_")
        }
    )

    database_engine.prepare_database(db_conn)

    db_conn.commit()


@defer.inlineCallbacks
def main(sqlite_config, mysql_config):
    try:
        sqlite_db_pool = adbapi.ConnectionPool(
            sqlite_config["name"],
            **sqlite_config["args"]
        )

        mysql_db_pool = adbapi.ConnectionPool(
            mysql_config["name"],
            **mysql_config["args"]
        )

        sqlite_engine = create_engine("sqlite3")
        mysql_engine = create_engine("mysql.connector")

        sqlite_store = Store(sqlite_db_pool, sqlite_engine)
        mysql_store = Store(mysql_db_pool, mysql_engine)

        # Step 1. Set up mysql database.
        logger.info("Preparing sqlite database...")
        setup_db(sqlite_config, sqlite_engine)

        logger.info("Preparing mysql database...")
        setup_db(mysql_config, mysql_engine)

        # Step 2. Get tables.
        logger.info("Fetching tables...")
        tables = yield sqlite_store._simple_select_onecol(
            table="sqlite_master",
            keyvalues={
                "type": "table",
            },
            retcol="name",
        )

        logger.info("Found %d tables", len(tables))

        # Process tables.
        yield defer.gatherResults(
            [
                handle_table(table, sqlite_store, mysql_store)
                for table in tables
                if table not in ["schema_version", "applied_schema_deltas"]
                and not table.startswith("sqlite_")
            ],
            consumeErrors=True,
        )

        # for table in ["current_state_events"]:  # tables:
        #     if table not in ["schema_version", "applied_schema_deltas"]:
        #         if not table.startswith("sqlite_"):
        #             yield handle_table(table, sqlite_store, mysql_store)
    except:
        logger.exception("")
    finally:
        reactor.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite-database")
    parser.add_argument(
        "--mysql-config", type=argparse.FileType('r'),
    )

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    sqlite_config = {
        "name": "sqlite3",
        "args": {
            "database": args.sqlite_database,
            "cp_min": 1,
            "cp_max": 1,
            "check_same_thread": False,
        },
    }

    mysql_config = yaml.safe_load(args.mysql_config)
    mysql_config["args"].update({
        "sql_mode": "TRADITIONAL",
        "charset": "utf8mb4",
        "use_unicode": True,
        "collation": "utf8mb4_bin",
    })

    import codecs
    codecs.register(
        lambda name: codecs.lookup('utf8') if name == "utf8mb4" else None
    )

    reactor.callWhenRunning(
        main,
        sqlite_config=sqlite_config,
        mysql_config=mysql_config,
    )

    reactor.run()
