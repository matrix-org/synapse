/* Copyright 2020 The Matrix.org Foundation C.I.C
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

-- register a background update which will create a unique index on
-- device_lists_outbound_last_success
INSERT into background_updates (ordering, update_name, progress_json)
    VALUES (5804, 'device_lists_outbound_last_success_unique_idx', '{}');

-- once that completes, we can drop the old index.
INSERT into background_updates (ordering, update_name, progress_json, depends_on)
    VALUES (
        5804,
        'drop_device_lists_outbound_last_success_non_unique_idx',
        '{}',
        'device_lists_outbound_last_success_unique_idx'
    );
