/* Copyright 2014, 2015 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS room_aliases(
    room_alias VARCHAR(150) NOT NULL,
    room_id VARCHAR(150) NOT NULL,
    UNIQUE (room_alias)
) ;

CREATE TABLE IF NOT EXISTS room_alias_servers(
    room_alias VARCHAR(150) NOT NULL,
    server VARCHAR(150) NOT NULL
) ;
