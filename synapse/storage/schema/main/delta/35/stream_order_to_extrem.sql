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


CREATE TABLE stream_ordering_to_exterm (
    stream_ordering BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
);

INSERT INTO stream_ordering_to_exterm (stream_ordering, room_id, event_id)
    SELECT stream_ordering, room_id, event_id FROM event_forward_extremities
    INNER JOIN (
        SELECT room_id, max(stream_ordering) as stream_ordering FROM events
        INNER JOIN event_forward_extremities USING (room_id, event_id)
        GROUP BY room_id
    ) AS rms USING (room_id);

CREATE INDEX stream_ordering_to_exterm_idx on stream_ordering_to_exterm(
    stream_ordering
);

CREATE INDEX stream_ordering_to_exterm_rm_idx on stream_ordering_to_exterm(
    room_id, stream_ordering
);
