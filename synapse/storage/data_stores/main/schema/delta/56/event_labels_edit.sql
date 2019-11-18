/* Copyright 2019 The Matrix.org Foundation C.I.C.
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

-- Track the ID of the event this event replaces (with a "m.replace" relation). This
-- exists so we can keep track of the changes in the list of labels associated with a
-- message.
ALTER TABLE event_labels ADD COLUMN replaces TEXT;

-- We need this index because we'll be querying labels which are either for a specific
-- event or for events that replace it.
CREATE INDEX event_labels_replaces_idx ON event_labels(replaces);