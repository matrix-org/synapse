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
        self._version = None  # unknown as yet

    def check_database(self, txn):
        txn.execute("SHOW SERVER_ENCODING")
        rows = txn.fetchall()
        if rows and rows[0][0] != "UTF8":
            raise IncorrectDatabaseSetup(
                "Database has incorrect encoding: '%s' instead of 'UTF8'\n"
                "See docs/postgres.rst for more information." % (rows[0][0],)
            )

    def convert_param_style(self, sql):
        return sql.replace("?", "%s")

    def on_new_connection(self, db_conn):

        # Get the version of PostgreSQL that we're using. As per the psycopg2
        # docs: The number is formed by converting the major, minor, and
        # revision numbers into two-decimal-digit numbers and appending them
        # together. For example, version 8.1.5 will be returned as 80105
        self._version = db_conn.server_version

        db_conn.set_isolation_level(
            self.module.extensions.ISOLATION_LEVEL_REPEATABLE_READ
        )

        # Set the bytea output to escape, vs the default of hex
        cursor = db_conn.cursor()
        cursor.execute("SET bytea_output TO escape")

        # Asynchronous commit, don't wait for the server to call fsync before
        # ending the transaction.
        # https://www.postgresql.org/docs/current/static/wal-async-commit.html
        if not self.synchronous_commit:
            cursor.execute("SET synchronous_commit TO OFF")

        cursor.close()

    @property
    def can_native_upsert(self):
        """
        Can we use native UPSERTs? This requires PostgreSQL 9.5+.
        """
        return self._version >= 90500

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

    def get_next_state_group_id(self, txn):
        """Returns an int that can be used as a new state_group ID
        """
        txn.execute("SELECT nextval('state_group_id_seq')")
        return txn.fetchone()[0]

    @property
    def server_version(self):
        """Returns a string giving the server version. For example: '8.1.5'

        Returns:
            string
        """
        # note that this is a bit of a hack because it relies on on_new_connection
        # having been called at least once. Still, that should be a safe bet here.
        numver = self._version
        assert numver is not None

        # https://www.postgresql.org/docs/current/libpq-status.html#LIBPQ-PQSERVERVERSION
        if numver >= 100000:
            return "%i.%i" % (numver / 10000, numver % 10000)
        else:
            return "%i.%i.%i" % (numver / 10000, (numver % 10000) / 100, numver % 100)
