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

-- Add new colums to the `events` table which will (one day) make the `state_events`
-- and `rejections` tables redundant.

ALTER TABLE events
  -- if this event is a state event, its state key
  ADD COLUMN state_key TEXT DEFAULT NULL;


ALTER TABLE events
  -- if this event was rejected, the reason it was rejected.
  ADD COLUMN rejection_reason TEXT DEFAULT NULL;
