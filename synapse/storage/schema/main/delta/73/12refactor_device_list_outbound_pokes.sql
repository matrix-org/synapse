/* Copyright 2022 The Matrix.org Foundation C.I.C
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

-- Prior to this schema delta, we tracked the set of unconverted rows in
-- `device_lists_changes_in_room` using the `converted_to_destinations` flag. When rows
-- were converted to `device_lists_outbound_pokes`, the `converted_to_destinations` flag
-- would be set.
--
-- After this schema delta, the `converted_to_destinations` is still populated like
-- before, but the set of unconverted rows is determined by the `stream_id` in the new
-- `device_lists_changes_converted_stream_position` table.
--
-- If rolled back, Synapse will re-send all device list changes that happened since the
-- schema delta.

CREATE TABLE IF NOT EXISTS device_lists_changes_converted_stream_position(
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    -- The (stream id, room id) of the last row in `device_lists_changes_in_room` that
    -- has been converted to `device_lists_outbound_pokes`. Rows with a strictly larger
    -- (stream id, room id) where `converted_to_destinations` is `FALSE` have not been
    -- converted.
    stream_id BIGINT NOT NULL,
    -- `room_id` may be an empty string, which compares less than all valid room IDs.
    room_id TEXT NOT NULL,
    CHECK (Lock='X')
);

INSERT INTO device_lists_changes_converted_stream_position (stream_id, room_id) VALUES (
    (
        SELECT COALESCE(
            -- The last converted stream id is the smallest unconverted stream id minus
            -- one.
            MIN(stream_id) - 1,
            -- If there is no unconverted stream id, the last converted stream id is the
            -- largest stream id.
            -- Otherwise, pick 1, since stream ids start at 2.
            (SELECT COALESCE(MAX(stream_id), 1) FROM device_lists_changes_in_room)
        ) FROM device_lists_changes_in_room WHERE NOT converted_to_destinations
    ),
    ''
);
