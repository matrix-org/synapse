/* Copyright 2019 Matrix.org Foundation CIC
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

-- version is supposed to be part of the room keys index
CREATE UNIQUE INDEX e2e_room_keys_with_version_idx ON e2e_room_keys(user_id, version, room_id, session_id);
DROP INDEX IF EXISTS e2e_room_keys_idx;
