# Copyright 2022 The Matrix.org Foundation C.I.C
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

import json

from synapse.storage.types import Cursor


def run_create(cur: Cursor, database_engine, *args, **kwargs):
    """Add a bg update to populate the `state_key` and `rejection_reason` columns of `events`"""

    # we know that any new events will have the columns populated (and that has been
    # the case since schema_version 68, so there is no chance of rolling back now).
    #
    # So, we only need to make sure that existing rows are updated. We read the
    # current min and max stream orderings, since that is guaranteed to include all
    # the events that were stored before the new columns were added.
    cur.execute("SELECT MIN(stream_ordering), MAX(stream_ordering) FROM events")
    (min_stream_ordering, max_stream_ordering) = cur.fetchone()

    if min_stream_ordering is None:
        # no rows, nothing to do.
        return

    cur.execute(
        "INSERT into background_updates (ordering, update_name, progress_json)"
        " VALUES (7203, 'events_populate_state_key_rejections', ?)",
        (
            json.dumps(
                {
                    "min_stream_ordering_exclusive": min_stream_ordering - 1,
                    "max_stream_ordering_inclusive": max_stream_ordering,
                }
            ),
        ),
    )
