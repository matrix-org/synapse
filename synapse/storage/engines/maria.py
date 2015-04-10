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

from synapse.storage import prepare_database

import types


class MariaEngine(object):
    def __init__(self, database_module):
        self.module = database_module

    def convert_param_style(self, sql):
        return sql.replace("?", "%s")

    def encode_parameter(self, param):
        if isinstance(param, types.BufferType):
            return bytes(param)
        return param

    def on_new_connection(self, db_conn):
        pass

    def prepare_database(self, db_conn):
        cur = db_conn.cursor()
        cur.execute(
            "ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
        )
        db_conn.commit()
        prepare_database(db_conn, self)

    def is_deadlock(self, error):
        if isinstance(error, self.module.DatabaseError):
            return error.sqlstate == "40001" and error.errno == 1213
        return False

    def load_unicode(self, v):
        return bytes(v).decode("UTF8")
