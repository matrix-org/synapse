#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

import logging

from synapse.storage.engines import create_engine

logger = logging.getLogger("create_postgres_db")

if __name__ == "__main__":
    # Create a PostgresEngine.
    db_engine = create_engine({"name": "psycopg2", "args": {}})

    # Connect to postgres to create the base database.
    # We use "postgres" as a database because it's bound to exist and the "synapse" one
    # doesn't exist yet.
    db_conn = db_engine.module.connect(
        user="postgres", host="postgres", password="postgres", dbname="postgres"
    )
    db_conn.autocommit = True
    cur = db_conn.cursor()
    cur.execute("CREATE DATABASE synapse;")
    cur.close()
    db_conn.close()
