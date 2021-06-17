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

-- Re-add some entries to stream_ordering_to_exterm that were incorrectly deleted
INSERT INTO stream_ordering_to_exterm (stream_ordering, room_id, event_id)
    SELECT
        (SELECT stream_ordering FROM events where event_id = e.event_id) AS stream_ordering,
        room_id,
        event_id
    FROM event_forward_extremities AS e
    WHERE NOT EXISTS (
        SELECT room_id FROM stream_ordering_to_exterm AS s
        WHERE s.room_id = e.room_id
    );
