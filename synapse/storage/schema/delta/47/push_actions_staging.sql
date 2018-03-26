/* Copyright 2018 New Vector Ltd
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

-- Temporary staging area for push actions that have been calculated for an
-- event, but the event hasn't yet been persisted.
-- When the event is persisted the rows are moved over to the
-- event_push_actions table.
CREATE TABLE event_push_actions_staging (
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    actions TEXT NOT NULL,
    notif SMALLINT NOT NULL,
    highlight SMALLINT NOT NULL
);

CREATE INDEX event_push_actions_staging_id ON event_push_actions_staging(event_id);
