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

-- Track the auth provider used by each login as well as the session ID
CREATE TABLE device_auth_providers (
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  auth_provider_id TEXT NOT NULL,
  auth_provider_session_id TEXT NOT NULL
);

CREATE INDEX device_auth_providers_devices
  ON device_auth_providers (user_id, device_id);
CREATE INDEX device_auth_providers_sessions
  ON device_auth_providers (auth_provider_id, auth_provider_session_id);
