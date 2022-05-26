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

CREATE TABLE receipts_ranged (
    stream_id bigint NOT NULL,
    room_id text NOT NULL,
    receipt_type text NOT NULL,
    user_id text NOT NULL,
    -- A null start means "everything before this".
    start_event_id text,
    end_event_id text NOT NULL,
    data text NOT NULL,
    instance_name text
);


CREATE INDEX receipts_ranged_id ON receipts_ranged (stream_id);
CREATE INDEX receipts_ranged_room_type_user ON receipts_ranged (room_id, receipt_type, user_id);
CREATE INDEX receipts_ranged_room_stream ON receipts_ranged (room_id, stream_id);
CREATE INDEX receipts_ranged_user ON receipts_ranged (user_id);
