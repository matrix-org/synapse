# Copyright 2018 New Vector Ltd
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

from synapse.storage.engines import PostgresEngine


def run_create(cur, database_engine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        # if we already have some state groups, we want to start making new
        # ones with a higher id.
        cur.execute("SELECT max(id) FROM state_groups")
        row = cur.fetchone()

        if row[0] is None:
            start_val = 1
        else:
            start_val = row[0] + 1

        cur.execute("CREATE SEQUENCE state_group_id_seq START WITH %s", (start_val,))


def run_upgrade(*args, **kwargs):
    pass
