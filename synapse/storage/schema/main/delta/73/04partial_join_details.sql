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

-- To ensure we correctly notify other homeservers about device list changes from our
-- users after a partial join transitions to a full join, we need to know when we began
-- the partial join. For now it's sufficient to know the device_list stream_id at the
-- time of the partial join, and the join event created for us during a partial join.
--
-- Both columns are backwards compatible.
ALTER TABLE partial_state_rooms ADD COLUMN device_lists_stream_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE partial_state_rooms ADD COLUMN join_event_id TEXT REFERENCES events(event_id);
