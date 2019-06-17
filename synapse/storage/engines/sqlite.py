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

import struct
import threading

from synapse.storage.prepare_database import prepare_database


class Sqlite3Engine(object):
    single_threaded = True

    def __init__(self, database_module, database_config):
        self.module = database_module

        # The current max state_group, or None if we haven't looked
        # in the DB yet.
        self._current_state_group_id = None
        self._current_state_group_id_lock = threading.Lock()

    @property
    def can_native_upsert(self):
        """
        Do we support native UPSERTs? This requires SQLite3 3.24+, plus some
        more work we haven't done yet to tell what was inserted vs updated.
        """
        return self.module.sqlite_version_info >= (3, 24, 0)

    def check_database(self, txn):
        pass

    def convert_param_style(self, sql):
        return sql

    def on_new_connection(self, db_conn):
        prepare_database(db_conn, self, config=None)
        db_conn.create_function("rank", 1, _rank)

    def is_deadlock(self, error):
        return False

    def is_connection_closed(self, conn):
        return False

    def lock_table(self, txn, table):
        return

    def get_next_state_group_id(self, txn):
        """Returns an int that can be used as a new state_group ID
        """
        # We do application locking here since if we're using sqlite then
        # we are a single process synapse.
        with self._current_state_group_id_lock:
            if self._current_state_group_id is None:
                txn.execute("SELECT COALESCE(max(id), 0) FROM state_groups")
                self._current_state_group_id = txn.fetchone()[0]

            self._current_state_group_id += 1
            return self._current_state_group_id

    @property
    def server_version(self):
        """Gets a string giving the server version. For example: '3.22.0'

        Returns:
            string
        """
        return "%i.%i.%i" % self.module.sqlite_version_info


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
