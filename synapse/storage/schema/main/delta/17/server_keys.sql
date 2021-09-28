/* Copyright 2015, 2016 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS server_keys_json (
    server_name TEXT, -- Server name.
    key_id TEXT, -- Requested key id.
    from_server TEXT, -- Which server the keys were fetched from.
    ts_added_ms INTEGER, -- When the keys were fetched
    ts_valid_until_ms INTEGER, -- When this version of the keys exipires.
    key_json bytea, -- JSON certificate for the remote server.
    CONSTRAINT uniqueness UNIQUE (server_name, key_id, from_server)
);
