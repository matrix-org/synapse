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

CREATE TABLE device_lists_changes_in_room (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,  -- This matches `device_lists_stream.stream_id`
    -- We have a background process which goes through this table and converts
    -- entries into rows in `device_lists_outbound_pokes`. Once we have processed
    -- a row, we mark it as such by setting `converted_to_destinations=TRUE`.
    converted_to_destinations BOOLEAN NOT NULL,
    opentracing_context TEXT
);

CREATE INDEX device_lists_changes_in_stream_id ON device_lists_changes_in_room(stream_id);
CREATE INDEX device_lists_changes_in_stream_id_converted ON device_lists_changes_in_room(stream_id) WHERE NOT converted_to_destinations;
