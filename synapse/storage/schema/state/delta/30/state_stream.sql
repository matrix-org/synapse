/* Copyright 2016 OpenMarket Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/* We used to create a table called current_state_resets, but this is no
 * longer used and is removed in delta 54.
 */

/* The outlier events that have aquired a state group typically through
 * backfill. This is tracked separately to the events table, as assigning a
 * state group change the position of the existing event in the stream
 * ordering.
 * However since a stream_ordering is assigned in persist_event for the
 * (event, state) pair, we can use that stream_ordering to identify when
 * the new state was assigned for the event.
 */
CREATE TABLE IF NOT EXISTS ex_outlier_stream(
    event_stream_ordering BIGINT PRIMARY KEY NOT NULL,
    event_id TEXT NOT NULL,
    state_group BIGINT NOT NULL
);
