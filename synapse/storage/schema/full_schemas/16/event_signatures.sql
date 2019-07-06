/* Copyright 2014-2016 OpenMarket Ltd
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

 /* We used to create tables called event_content_hashes and event_edge_hashes,
  * but these are no longer used and are removed in delta 54.
  */

CREATE TABLE IF NOT EXISTS event_reference_hashes (
    event_id TEXT,
    algorithm TEXT,
    hash bytea,
    UNIQUE (event_id, algorithm)
);

CREATE INDEX event_reference_hashes_id ON event_reference_hashes(event_id);


CREATE TABLE IF NOT EXISTS event_signatures (
    event_id TEXT,
    signature_name TEXT,
    key_id TEXT,
    signature bytea,
    UNIQUE (event_id, signature_name, key_id)
);

CREATE INDEX event_signatures_id ON event_signatures(event_id);
