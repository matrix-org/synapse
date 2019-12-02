/* Copyright 2017 Vector Creations Ltd
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


-- Table of last stream_id that we sent to destination for user_id. This is
-- used to fill out the `prev_id` fields of outbound device list updates.
CREATE TABLE device_lists_outbound_last_success (
    destination TEXT NOT NULL,
    user_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL
);

INSERT INTO device_lists_outbound_last_success
    SELECT destination, user_id, coalesce(max(stream_id), 0) as stream_id
        FROM device_lists_outbound_pokes
        WHERE sent = (1 = 1)  -- sqlite doesn't have inbuilt boolean values
        GROUP BY destination, user_id;

CREATE INDEX device_lists_outbound_last_success_idx ON device_lists_outbound_last_success(
    destination, user_id, stream_id
);
