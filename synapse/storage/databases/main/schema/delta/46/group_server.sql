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

CREATE TABLE groups_new (
    group_id TEXT NOT NULL,
    name TEXT,  -- the display name of the room
    avatar_url TEXT,
    short_description TEXT,
    long_description TEXT,
    is_public BOOL NOT NULL -- whether non-members can access group APIs
);

-- NB: awful hack to get the default to be true on postgres and 1 on sqlite
INSERT INTO groups_new
    SELECT group_id, name, avatar_url, short_description, long_description, (1=1) FROM groups;

DROP TABLE groups;
ALTER TABLE groups_new RENAME TO groups;

CREATE UNIQUE INDEX groups_idx ON groups(group_id);
