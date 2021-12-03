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

-- Track the auth provider used by this login as well as the session ID
ALTER TABLE devices
  ADD COLUMN auth_provider_id TEXT;
ALTER TABLE devices
  ADD COLUMN auth_provider_session_id TEXT;

CREATE INDEX devices_auth_provider_session_id ON devices (auth_provider_id, auth_provider_session_id);
