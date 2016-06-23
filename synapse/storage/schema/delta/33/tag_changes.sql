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

CREATE TABLE room_tags_change_revisions(
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    change TEXT NOT NULL
);

CREATE INDEX room_tags_change_revisions_rm_idx ON room_tags_change_revisions(user_id, room_id, stream_id);
CREATE INDEX room_tags_change_revisions_idx ON room_tags_change_revisions(user_id, stream_id);
