/* Copyright 2018 New Vector Ltd
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

ALTER TABLE events ADD COLUMN IF NOT EXISTS thread_id BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS events_room_idx ON events (room_id, thread_id);

-- CREATE SEQUENCE thread_id_seq;


CREATE INDEX IF NOT EXISTS event_room_thread_ts ON events (room_id, thread_id, origin_server_ts);
