/* Copyright 2017 New Vector Ltd
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

-- drop the unique constraint on deleted_pushers so that we can just insert
-- into it rather than upserting.

CREATE TABLE deleted_pushers2 (
    stream_id BIGINT NOT NULL,
    app_id TEXT NOT NULL,
    pushkey TEXT NOT NULL,
    user_id TEXT NOT NULL
);

INSERT INTO deleted_pushers2 (stream_id, app_id, pushkey, user_id)
    SELECT stream_id, app_id, pushkey, user_id from deleted_pushers;

DROP TABLE deleted_pushers;
ALTER TABLE deleted_pushers2 RENAME TO deleted_pushers;

-- create the index after doing the inserts because that's more efficient.
-- it also means we can give it the same name as the old one without renaming.
CREATE INDEX deleted_pushers_stream_id ON deleted_pushers (stream_id);

