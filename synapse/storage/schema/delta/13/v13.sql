/* Copyright 2015 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS application_services(
    id INTEGER PRIMARY KEY,
    url VARCHAR(255),
    token VARCHAR(255),
    hs_token VARCHAR(255),
    sender VARCHAR(255),
    UNIQUE(token)
);

CREATE TABLE IF NOT EXISTS application_services_regex(
    id INTEGER PRIMARY KEY,
    as_id INTEGER NOT NULL,
    namespace INTEGER,  /* enum[room_id|room_alias|user_id] */
    regex VARCHAR(255),
    FOREIGN KEY(as_id) REFERENCES application_services(id)
);
