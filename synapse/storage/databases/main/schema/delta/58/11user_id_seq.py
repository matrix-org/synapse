# Copyright 2020 The Matrix.org Foundation C.I.C.
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

"""
Adds a postgres SEQUENCE for generating guest user IDs.
"""

from synapse.storage.databases.main.registration import (
    find_max_generated_user_id_localpart,
)
from synapse.storage.engines import PostgresEngine


def run_create(cur, database_engine, *args, **kwargs):
    if not isinstance(database_engine, PostgresEngine):
        return

    next_id = find_max_generated_user_id_localpart(cur) + 1
    cur.execute("CREATE SEQUENCE user_id_seq START WITH %s", (next_id,))


def run_upgrade(*args, **kwargs):
    pass
