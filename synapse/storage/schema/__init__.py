# Copyright 2021 The Matrix.org Foundation C.I.C.
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

SCHEMA_VERSION = 83  # remember to update the list below when updating
"""Represents the expectations made by the codebase about the database schema

This should be incremented whenever the codebase changes its requirements on the
shape of the database schema (even if those requirements are backwards-compatible with
older versions of Synapse).

See https://matrix-org.github.io/synapse/develop/development/database_schema.html
for more information on how this works.

Changes in SCHEMA_VERSION = 61:
    - The `user_stats_historical` and `room_stats_historical` tables are not written and
      are not read (previously, they were written but not read).
    - MSC2716: Add `insertion_events` and `insertion_event_edges` tables to keep track
      of insertion events in order to navigate historical chunks of messages.
    - MSC2716: Add `chunk_events` table to track how the chunk is labeled and
      determines which insertion event it points to.

Changes in SCHEMA_VERSION = 62:
    - MSC2716: Add `insertion_event_extremities` table that keeps track of which
      insertion events need to be backfilled.

Changes in SCHEMA_VERSION = 63:
    - The `public_room_list_stream` table is not written nor read to
      (previously, it was written and read to, but not for any significant purpose).
      https://github.com/matrix-org/synapse/pull/10565

Changes in SCHEMA_VERSION = 64:
    - MSC2716: Rename related tables and columns from "chunks" to "batches".

Changes in SCHEMA_VERSION = 65:
    - MSC2716: Remove unique event_id constraint from insertion_event_edges
      because an insertion event can have multiple edges.
    - Remove unused tables `user_stats_historical` and `room_stats_historical`.

Changes in SCHEMA_VERSION = 66:
    - Queries on state_key columns are now disambiguated (ie, the codebase can handle
      the `events` table having a `state_key` column).

Changes in SCHEMA_VERSION = 67:
    - state_events.prev_state is no longer written to.

Changes in SCHEMA_VERSION = 68:
    - event_reference_hashes is no longer read.
    - `events` has `state_key` and `rejection_reason` columns, which are populated for
      new events.

Changes in SCHEMA_VERSION = 69:
    - We now write to `device_lists_changes_in_room` table.
    - We now use a PostgreSQL sequence to generate future txn_ids for
      `application_services_txns`. `application_services_state.last_txn` is no longer
      updated.

Changes in SCHEMA_VERSION = 70:
    - event_reference_hashes is no longer written to.

Changes in SCHEMA_VERSION = 71:
    - event_edges.room_id is no longer read from.
    - Tables related to groups are no longer accessed.

Changes in SCHEMA_VERSION = 72:
    - event_edges.(room_id, is_state) are no longer written to.
    - Tables related to groups are dropped.
    - Unused column application_services_state.last_txn is dropped
    - Cache invalidation stream id sequence now begins at 2 to match code expectation.

Changes in SCHEMA_VERSION = 73:
    - thread_id column is added to event_push_actions, event_push_actions_staging
      event_push_summary, receipts_linearized, and receipts_graph.
    - Add table `event_failed_pull_attempts` to keep track when we fail to pull
      events over federation.
    - Add indexes to various tables (`event_failed_pull_attempts`, `insertion_events`,
      `batch_events`) to make it easy to delete all associated rows when purging a room.
    - `inserted_ts` column is added to `event_push_actions_staging` table.

Changes in SCHEMA_VERSION = 74:
    - A query on `event_stream_ordering` column has now been disambiguated (i.e. the
      codebase can handle the `current_state_events`, `local_current_memberships` and
      `room_memberships` tables having an `event_stream_ordering` column).

Changes in SCHEMA_VERSION = 75:
    - The `event_stream_ordering` column in membership tables (`current_state_events`,
      `local_current_membership` & `room_memberships`) is now being populated for new
      rows. When the background job to populate historical rows lands this will
      become the compat schema version.

Changes in SCHEMA_VERSION = 76:
    - Adds a full_user_id column to tables profiles and user_filters.

Changes in SCHEMA_VERSION = 77
    - (Postgres) Add NOT VALID CHECK (full_user_id IS NOT NULL) to tables profiles and user_filters

Changes in SCHEMA_VERSION = 78
    - Validate check (full_user_id IS NOT NULL) on tables profiles and user_filters

Changes in SCHEMA_VERSION = 79
    - Add tables to handle in DB read-write locks.
    - Add some mitigations for a painful race between foreground and background updates, cf
      https://github.com/matrix-org/synapse/issues/15677.

Changes in SCHEMA_VERSION = 80
    - The event_txn_id_device_id is always written to for new events.
    - Add tables for the task scheduler.

Changes in SCHEMA_VERSION = 81
    - The event_txn_id is no longer written to for new events.

Changes in SCHEMA_VERSION = 82
    - The insertion_events, insertion_event_extremities, insertion_event_edges, and
      batch_events tables are no longer purged in preparation for their removal.

Changes in SCHEMA_VERSION = 83
    - The event_txn_id is no longer used.
"""


SCHEMA_COMPAT_VERSION = (
    # The event_txn_id table and tables from MSC2716 no longer exist.
    83
)
"""Limit on how far the synapse codebase can be rolled back without breaking db compat

This value is stored in the database, and checked on startup. If the value in the
database is greater than SCHEMA_VERSION, then Synapse will refuse to start.
"""
