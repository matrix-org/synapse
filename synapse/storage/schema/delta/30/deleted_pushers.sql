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

CREATE TABLE IF NOT EXISTS deleted_pushers(
    stream_id BIGINT NOT NULL,
    app_id TEXT NOT NULL,
    pushkey TEXT NOT NULL,
    user_id TEXT NOT NULL,
    /* We only track the most recent delete for each app_id, pushkey and user_id. */
    UNIQUE (app_id, pushkey, user_id)
);

CREATE INDEX deleted_pushers_stream_id ON deleted_pushers (stream_id);
