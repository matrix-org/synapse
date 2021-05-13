/* Copyright 2015, 2016 OpenMarket Ltd
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


CREATE TABLE IF NOT EXISTS room_tags(
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    tag     TEXT NOT NULL,  -- The name of the tag.
    content TEXT NOT NULL,  -- The JSON content of the tag.
    CONSTRAINT room_tag_uniqueness UNIQUE (user_id, room_id, tag)
);

CREATE TABLE IF NOT EXISTS room_tags_revisions (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL, -- The current version of the room tags.
    CONSTRAINT room_tag_revisions_uniqueness UNIQUE (user_id, room_id)
);

CREATE TABLE IF NOT EXISTS private_user_data_max_stream_id(
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    stream_id  BIGINT NOT NULL,
    CHECK (Lock='X')
);

INSERT INTO private_user_data_max_stream_id (stream_id) VALUES (0);
