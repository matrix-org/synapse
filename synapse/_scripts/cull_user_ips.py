# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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

from __future__ import print_function

import argparse
from collections import defaultdict

import yaml

from synapse.storage.engines.postgres import PostgresEngine
from synapse.storage.engines.sqlite3 import Sqlite3Engine


def _main(conn, engine, _print=print):

    cur = conn.cursor()

    def _run(sql, *args):
        cur.execute(engine.convert_param_style(sql), *args)

    # Get all the users
    _run("SELECT name from users;")
    users = cur.fetchall()

    for user in users:
        uid = user[0]

        _print("Processing user %s" % (uid,))

        # Get the user's valid access tokens
        _run("SELECT token FROM access_tokens WHERE user_id = ?;", (uid,))
        user_tokens = {x[0] for x in cur.fetchall()}

        # Get the user's rows from the user_ips table
        _run("SELECT access_token, last_seen FROM user_ips WHERE user_id = ?;", (uid,))
        rows = cur.fetchall()
        _print("Got %s rows" % (len(rows),))

        # map of access token -> set of timestamps
        tokens = defaultdict(set)

        for row in rows:
            tokens[row[0]].add(row[1])

        # We now know what user access tokens are valid, so we can determine
        # which out of date access tokens we can remove
        invalid_tokens = set(tokens.keys()) - user_tokens
        valid_tokens = set(tokens.keys()) & user_tokens

        # Delete access tokens that are not current from the user_ips table
        if invalid_tokens:
            _print("Deleting %d invalid tokens" % (len(invalid_tokens),))

            for i in invalid_tokens:
                _run(
                    "DELETE FROM user_ips WHERE user_id = ? AND access_token = ?;",
                    (uid, i),
                )

        # Delete entries for valid access tokens that are older than the most recent
        for token in valid_tokens:
            if len(tokens[token]) == 1:
                continue
            max_last_seen = max(tokens[token])
            _print("Deleting %d old rows" % (len(tokens[token]) - 1,))
            _run(
                (
                    "DELETE FROM user_ips WHERE user_id = ? AND access_token = ? "
                    "AND last_seen < ?;"
                ),
                (uid, token, max_last_seen),
            )

        # Determine what effect we had
        _run("SELECT last_seen FROM user_ips WHERE user_id = ?;", (uid,))
        new_rows = cur.fetchall()
        _print("Cleaned up %s rows" % (len(rows) - len(new_rows),))

        # Commit the changes to the database
        conn.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=("Cull the user_ips database."))
    parser.add_argument(
        "-c",
        "--config",
        type=argparse.FileType('r'),
        help=("Path to server config file. Used to read database configuration."),
    )

    args = parser.parse_args()
    assert "config" in args, "Need configuration"
    assert args.config, "Need configuration"

    config = yaml.safe_load(args.config)

    # Set up the database.
    db_type = config["database"]["name"]
    db_params = {
        k: v for k, v in config["database"]["args"].items() if not k.startswith("cp_")
    }

    if db_type == "sqlite3":
        import sqlite3 as db_module

        engine = Sqlite3Engine(db_module, {})
    elif db_type == "psycopg2":
        import psycopg2 as db_module

        engine = PostgresEngine(db_module, {})

    conn = db_module.connect(**db_params)

    _main(conn, engine)
