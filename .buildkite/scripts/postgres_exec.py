#!/usr/bin/env python
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

import sys

import psycopg2

# a very simple replacment for `psql`, to make up for the lack of the postgres client
# libraries in the synapse docker image.

# We use "postgres" as a database because it's bound to exist and the "synapse" one
# doesn't exist yet.
db_conn = psycopg2.connect(
    user="postgres", host="postgres", password="postgres", dbname="postgres"
)
db_conn.autocommit = True
cur = db_conn.cursor()
for c in sys.argv[1:]:
    cur.execute(c)
