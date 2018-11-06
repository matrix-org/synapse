/* Copyright 2018 New Vector Ltd
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

-- attestations of e2e device keys
CREATE TABLE e2e_attestations (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    attestation TEXT NOT NULL
);

CREATE INDEX e2e_attestations_idx ON e2e_attestations(user_id, from_user_id, device_id);
