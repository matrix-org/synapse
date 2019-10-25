/* Copyright 2019 New Vector Ltd
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

-- Tracks related events, like reactions, replies, edits, etc. Note that things
-- in this table are not necessarily "valid", e.g. it may contain edits from
-- people who don't have power to edit other peoples events.
CREATE TABLE IF NOT EXISTS event_relations (
    event_id TEXT NOT NULL,
    relates_to_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    aggregation_key TEXT
);

CREATE UNIQUE INDEX event_relations_id ON event_relations(event_id);
CREATE INDEX event_relations_relates ON event_relations(relates_to_id, relation_type, aggregation_key);
