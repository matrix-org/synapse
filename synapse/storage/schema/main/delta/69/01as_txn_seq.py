# Copyright 2022 Beeper
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
Adds a postgres SEQUENCE for generating application service transaction IDs.
"""

from synapse.storage.engines import PostgresEngine


def run_create(cur, database_engine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        # If we already have some AS TXNs we want to start from the current
        # maximum value. There are two potential places this is stored - the
        # actual TXNs themselves *and* the AS state table. At time of migration
        # it is possible the TXNs table is empty so we must include the AS state
        # last_txn as a potential option, and pick the maximum.

        cur.execute("SELECT COALESCE(max(txn_id), 0) FROM application_services_txns")
        row = cur.fetchone()
        txn_max = row[0]

        cur.execute("SELECT COALESCE(max(last_txn), 0) FROM application_services_state")
        row = cur.fetchone()
        last_txn_max = row[0]

        start_val = max(last_txn_max, txn_max) + 1

        cur.execute(
            "CREATE SEQUENCE application_services_txn_id_seq START WITH %s",
            (start_val,),
        )
