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

-- Drop the old event transaction ID table, the event_txn_id_device_id table
-- should be used instead.
DROP TABLE IF EXISTS event_txn_id;

-- Drop tables related to MSC2716 since the implementation is being removed
DROP TABLE IF EXISTS insertion_events;
DROP TABLE IF EXISTS insertion_event_edges;
DROP TABLE IF EXISTS insertion_event_extremities;
DROP TABLE IF EXISTS batch_events;
