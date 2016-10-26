/* Copyright 2016 OpenMarket Ltd
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



CREATE TABLE profiles_extended (
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    persona TEXT NOT NULL,
    key TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE INDEX profiles_extended_tuple ON profiles_extended(user_id, persona, key, stream_id);
