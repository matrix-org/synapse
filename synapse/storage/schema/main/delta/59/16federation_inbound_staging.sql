/* Copyright 2021 The Matrix.org Foundation C.I.C
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


-- A staging area for newly received events over federation.
--
-- Note we may store the same event multiple times if it comes from different
-- servers; this is to handle the case if we get a redacted and non-redacted
-- versions of the event.
CREATE TABLE federation_inbound_events_staging (
    origin TEXT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    received_ts BIGINT NOT NULL,
    event_json TEXT NOT NULL,
    internal_metadata TEXT NOT NULL
);

CREATE INDEX federation_inbound_events_staging_room ON federation_inbound_events_staging(room_id, received_ts);
CREATE UNIQUE INDEX federation_inbound_events_staging_instance_event ON federation_inbound_events_staging(origin, event_id);
