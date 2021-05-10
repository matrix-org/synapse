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

-- register a background update which will recreate the
-- local_media_repository_url_idx index.
--
-- We do this as a bg update not because it is a particularly onerous
-- operation, but because we'd like it to be a partial index if possible, and
-- the background_index_update code will understand whether we are on
-- postgres or sqlite and behave accordingly.
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('local_media_repository_url_idx', '{}');
