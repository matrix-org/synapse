/* Copyright 2023 The Matrix.org Foundation C.I.C
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

ALTER TABLE user_filters ADD COLUMN full_user_id TEXT;

-- Add a unique index on the new column, mirroring the `user_filters_unique` unique
-- index.
CREATE UNIQUE INDEX full_user_filters_unique ON user_filters (full_user_id, filter_id);
-- NB: This will lock the table for writes while the index is being built.
--     There are around 4,000,000 user_filters on matrix.org so we expect this to take
--     a couple of seconds at most.