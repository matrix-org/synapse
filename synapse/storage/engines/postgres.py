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


class PostgresEngine(object):
    def __init__(self, database_module):
        self.module = database_module
        self.module.extensions.register_type(self.module.extensions.UNICODE)

    def convert_param_style(self, sql):
        return sql.replace("?", "%s")

    def encode_parameter(self, param):
        return param

    def on_new_connection(self, db_conn):
        db_conn.set_isolation_level(
            self.module.extensions.ISOLATION_LEVEL_REPEATABLE_READ
        )

    def prepare_database(self, db_conn):
        prepare_database(db_conn, self)

    def is_deadlock(self, error):
        if isinstance(error, self.module.DatabaseError):
            return error.pgcode == "40P01"
        return False

    def load_unicode(self, v):
        return bytes(v).decode("UTF8")
