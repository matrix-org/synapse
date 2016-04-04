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


CREATE TABLE invites(
    stream_id BIGINT NOT NULL,
    inviter TEXT NOT NULL,
    invitee TEXT NOT NULL,
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    locally_rejected TEXT,
    replaced_by TEXT
);

CREATE INDEX invites_id ON invites(stream_id);
CREATE INDEX invites_for_user_idx ON invites(invitee, locally_rejected, replaced_by, room_id);
