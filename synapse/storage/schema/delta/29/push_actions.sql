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

ALTER TABLE event_push_actions ADD COLUMN topological_ordering BIGINT;
ALTER TABLE event_push_actions ADD COLUMN stream_ordering BIGINT;
ALTER TABLE event_push_actions ADD COLUMN notif SMALLINT;
ALTER TABLE event_push_actions ADD COLUMN highlight SMALLINT;

UPDATE event_push_actions SET stream_ordering = (
    SELECT stream_ordering FROM events WHERE event_id = event_push_actions.event_id
), topological_ordering = (
    SELECT topological_ordering FROM events WHERE event_id = event_push_actions.event_id
);

UPDATE event_push_actions SET notif = 1, highlight = 0;

CREATE INDEX event_push_actions_rm_tokens on event_push_actions(
    user_id, room_id, topological_ordering, stream_ordering
);
