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

from ._base import IncorrectDatabaseSetup


class PostgresEngine(object):
    single_threaded = False

    def __init__(self, database_module, database_config):
        self.module = database_module
        self.module.extensions.register_type(self.module.extensions.UNICODE)
        self.synchronous_commit = database_config.get("synchronous_commit", True)

    def check_database(self, txn):
        txn.execute("SHOW SERVER_ENCODING")
        rows = txn.fetchall()
        if rows and rows[0][0] != "UTF8":
            raise IncorrectDatabaseSetup(
                "Database has incorrect encoding: '%s' instead of 'UTF8'\n"
                "See docs/postgres.rst for more information."
                % (rows[0][0],)
            )

    def convert_param_style(self, sql):
        return sql.replace("?", "%s")

    def on_new_connection(self, db_conn):
        db_conn.set_isolation_level(
            self.module.extensions.ISOLATION_LEVEL_REPEATABLE_READ
        )
        # Asynchronous commit, don't wait for the server to call fsync before
        # ending the transaction.
        # https://www.postgresql.org/docs/current/static/wal-async-commit.html
        if not self.synchronous_commit:
            cursor = db_conn.cursor()
            cursor.execute("SET synchronous_commit TO OFF")
            cursor.close()

    def is_deadlock(self, error):
        if isinstance(error, self.module.DatabaseError):
            # https://www.postgresql.org/docs/current/static/errcodes-appendix.html
            # "40001" serialization_failure
            # "40P01" deadlock_detected
            return error.pgcode in ["40001", "40P01"]
        return False

    def is_connection_closed(self, conn):
        return bool(conn.closed)

    def lock_table(self, txn, table):
        txn.execute("LOCK TABLE %s in EXCLUSIVE MODE" % (table,))
