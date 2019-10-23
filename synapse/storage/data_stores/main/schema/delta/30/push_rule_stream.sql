/* Copyright 2016 OpenMarket Ltd
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



CREATE TABLE push_rules_stream(
    stream_id BIGINT NOT NULL,
    event_stream_ordering BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    op TEXT NOT NULL, -- One of "ENABLE", "DISABLE", "ACTIONS", "ADD", "DELETE"
    priority_class SMALLINT,
    priority INTEGER,
    conditions TEXT,
    actions TEXT
);

-- The extra data for each operation is:
-- * ENABLE, DISABLE, DELETE: []
-- * ACTIONS: ["actions"]
-- * ADD: ["priority_class", "priority", "actions", "conditions"]

-- Index for replication queries.
CREATE INDEX push_rules_stream_id ON push_rules_stream(stream_id);
-- Index for /sync queries.
CREATE INDEX push_rules_stream_user_stream_id on push_rules_stream(user_id, stream_id);
