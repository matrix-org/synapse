# Copyright 2023 The Matrix.org Foundation C.I.C.
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
This migration adds foreign key constraint to `event_forward_extremities` table.
"""
from synapse.storage.background_updates import (
    ForeignKeyConstraint,
    run_validate_constraint_and_delete_rows_schema_delta,
)
from synapse.storage.database import LoggingTransaction
from synapse.storage.engines import BaseDatabaseEngine

FORWARD_EXTREMITIES_TABLE_SCHEMA = """
    CREATE TABLE event_forward_extremities2(
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        UNIQUE (event_id, room_id),
        CONSTRAINT event_forward_extremities_event_id FOREIGN KEY (event_id) REFERENCES events (event_id) DEFERRABLE INITIALLY DEFERRED
    )
"""


def run_create(cur: LoggingTransaction, database_engine: BaseDatabaseEngine) -> None:
    # We mark this as a deferred constraint, as the previous version of Synapse
    # inserted the event into the forward extremities *before* the events table.
    # By marking as deferred we ensure that downgrading to the previous version
    # will continue to work.
    run_validate_constraint_and_delete_rows_schema_delta(
        cur,
        ordering=7803,
        update_name="event_forward_extremities_event_id_foreign_key_constraint_update",
        table="event_forward_extremities",
        constraint_name="event_forward_extremities_event_id",
        constraint=ForeignKeyConstraint(
            "events", [("event_id", "event_id")], deferred=True
        ),
        sqlite_table_name="event_forward_extremities2",
        sqlite_table_schema=FORWARD_EXTREMITIES_TABLE_SCHEMA,
    )

    # We can't add a similar constraint to `event_backward_extremities` as the
    # events in there don't exist in the `events` table and `event_edges`
    # doesn't have a unique constraint on `prev_event_id` (so we can't make a
    # foreign key point to it).
