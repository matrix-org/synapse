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

import argparse
from collections import defaultdict
import yaml

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Cull the user_ips database."
        )
    )
    parser.add_argument(
        "-c",
        "--config",
        type=argparse.FileType('r'),
        help=(
            "Path to server config file. "
            "Used to read database configuration."
        ),
    )


    args = parser.parse_args()
    assert "config" in args, "Need configuration"
    assert args.config, "Need configuration"

    config = yaml.safe_load(args.config)

    db_type = config["database"]["name"]
    db_config = config["database"]["args"]

    db_params = {
        k: v for k, v in db_config.items()
        if not k.startswith("cp_")
    }

    if db_type == "sqlite3":
        import sqlite3 as db_module
        key = "?"
    elif db_type == "psycopg2":
        import psycopg2 as db_module
        key = "%s"

    conn = db_module.connect(**db_params)

    cur = conn.cursor()
    cur.execute("SELECT name from users;")
    users = cur.fetchall()

    for user in users:
        uid = user[0]

        print("Processing user %s" % (uid,))

        # Get their access tokens
        cur.execute("SELECT token FROM access_tokens WHERE user_id = " + key + ";", (uid,))
        user_tokens = {x[0] for x in cur.fetchall()}

        print("Got %d valid tokens" % (len(user_tokens),))

        cur.execute("SELECT access_token, last_seen FROM user_ips WHERE user_id = " + key + ";", (uid,))
        rows = cur.fetchall()
        print("Got %s rows" % (len(rows),))

        tokens = defaultdict(set)

        # Create buckets per access token
        for row in rows:
            tokens[row[0]].add(row[1])

        print("Got %d stores tokens" % (len(tokens),))

        invalid_tokens = set(tokens.keys()) ^ user_tokens
        valid_tokens = set(tokens.keys()) & user_tokens

        if invalid_tokens:
            print("Deleting %d invalid tokens" % (len(invalid_tokens),))

            for i in invalid_tokens:
                cur.execute("DELETE FROM user_ips WHERE user_id = " + key + " AND access_token = " + key + ";", (uid, i))

        for token in valid_tokens:
            max_last_seen = max(tokens[token])
            cur.execute("DELETE FROM user_ips WHERE user_id = " + key + " AND access_token = " + key + " AND last_seen < " + key + ";", (uid, i, max_last_seen))

        cur.execute("SELECT last_seen FROM user_ips WHERE user_id = " + key + ";", (uid,))
        new_rows = cur.fetchall()
        print("Cleaned up %s rows" % (len(rows) - len(new_rows),))

        conn.commit()

