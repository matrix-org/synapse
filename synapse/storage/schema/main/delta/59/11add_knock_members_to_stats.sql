/* Copyright 2020 Sorunome
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

-- Existing rows will default to NULL, so anything reading from these tables
-- needs to interpret NULL as 0. This is fine here as no existing rooms can have
-- any knocked members.
ALTER TABLE room_stats_current ADD COLUMN knocked_members INT;
ALTER TABLE room_stats_historical ADD COLUMN knocked_members BIGINT;
