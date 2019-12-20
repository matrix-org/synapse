/* Copyright 2019 The Matrix.org Foundation C.I.C.
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

-- This line already existed in deltas/35/device_stream_id but was not included in the
-- 54 full schema SQL. Add some SQL here to insert the missing row if it does not exist
INSERT INTO device_max_stream_id (stream_id) SELECT 0 WHERE NOT EXISTS (
    SELECT * from device_max_stream_id
);