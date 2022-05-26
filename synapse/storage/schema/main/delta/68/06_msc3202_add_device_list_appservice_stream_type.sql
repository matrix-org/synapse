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

-- Add a column to track what device list changes stream id that this application
-- service has been caught up to.

-- We explicitly don't set this field as "NOT NULL", as having NULL as a possible
-- state is useful for determining if we've ever sent traffic for a stream type
-- to an appservice. See https://github.com/matrix-org/synapse/issues/10836 for
-- one way this can be used.
ALTER TABLE application_services_state ADD COLUMN device_list_stream_id BIGINT;