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
import yaml

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Delete duplicate rows in the "
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

    config = yaml.safe_load(args.config)

    db_type = config["database"]["name"]
    db_config = config["database"]["args"]

    db_params = {
        k: v for k, v in db_config.get("args", {}).items()
        if not k.startswith("cp_")
    }

    if db_type == "sqlite3":
        import sqlite3 as db_module
    elif db_type == "psycopg2":
        import psycopg2 as db_module

    conn = db_module.connect(**db_params)

    cur = conn.cursor()

    cur.execute("SELECT FROM user_ips T1 USING user_ips T2 WHERE T1.user == T2.user AND T1.access_token == T2.access_token AND T1.device_id == T2.device_id AND T1.ip == T2.ip AND T1.user_agent == T2.user_agent AND T1.last_seen < T2.last_seen;")

    res = cur.fetchall()

    print(res)