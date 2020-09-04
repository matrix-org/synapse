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

-- This column tracks the stream_ordering of the event that was most recently
-- successfully transmitted to the destination.
-- A value of NULL means that we have not sent an event successfully yet
-- (at least, not since the introduction of this column).
ALTER TABLE destinations
    ADD COLUMN last_successful_stream_ordering BIGINT;
