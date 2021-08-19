/* Copyright 2021 Callum Brown
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

CREATE TABLE IF NOT EXISTS registration_tokens(
    token TEXT NOT NULL,  -- The token that can be used for authentication.
    uses_allowed INT,  -- The total number of times this token can be used. NULL if no limit.
    pending INT NOT NULL, -- The number of in progress registrations using this token.
    completed INT NOT NULL, -- The number of times this token has been used to complete a registration.
    expiry_time BIGINT,  -- The latest time this token will be valid (epoch time in milliseconds). NULL if token doesn't expire.
    UNIQUE (token)
);
