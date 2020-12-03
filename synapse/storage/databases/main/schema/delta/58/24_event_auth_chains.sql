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

CREATE SEQUENCE IF NOT EXISTS event_auth_chain_id;

CREATE TABLE event_auth_chains (
  event_id TEXT PRIMARY KEY,
  chain_id BIGINT NOT NULL,
  sequence_number BIGINT NOT NULL
);

CREATE UNIQUE INDEX ON event_auth_chains (chain_id, sequence_number);


CREATE TABLE event_auth_chain_links (
  origin_chain_id BIGINT NOT NULL,
  origin_sequence_number BIGINT NOT NULL,

  target_chain_id BIGINT NOT NULL,
  target_sequence_number BIGINT NOT NULL
);


CREATE INDEX ON event_auth_chain_links (origin_chain_id, target_chain_id);


-- Whether we've calculated the above index for a room.
ALTER TABLE rooms ADD COLUMN has_auth_chain_index BOOLEAN;
