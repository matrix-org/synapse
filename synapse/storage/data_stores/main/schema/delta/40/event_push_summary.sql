/* Copyright 2017 OpenMarket Ltd
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

-- Aggregate of old notification counts that have been deleted out of the
-- main event_push_actions table. This count does not include those that were
-- highlights, as they remain in the event_push_actions table.
CREATE TABLE event_push_summary (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    notif_count BIGINT NOT NULL,
    stream_ordering BIGINT NOT NULL
);

CREATE INDEX event_push_summary_user_rm ON event_push_summary(user_id, room_id);


-- The stream ordering up to which we have aggregated the event_push_actions
-- table into event_push_summary
CREATE TABLE event_push_summary_stream_ordering (
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    stream_ordering BIGINT NOT NULL,
    CHECK (Lock='X')
);

INSERT INTO event_push_summary_stream_ordering (stream_ordering) VALUES (0);
