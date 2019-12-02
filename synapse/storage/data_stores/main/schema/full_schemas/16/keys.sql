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

-- we used to create a table called server_tls_certificates, but this is no
-- longer used, and is removed in delta 54.

CREATE TABLE IF NOT EXISTS server_signature_keys(
  server_name TEXT, -- Server name.
  key_id TEXT, -- Key version.
  from_server TEXT, -- Which key server the key was fetched form.
  ts_added_ms BIGINT, -- When the key was added.
  verify_key bytea, -- NACL verification key.
  UNIQUE (server_name, key_id)
);
