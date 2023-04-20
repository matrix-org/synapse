/* Copyright 2023 Beeper Inc.
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

-- Add new colums to the `local_media_repository` to keep track of when the
-- media ID must be used by. This is to support async uploads (see MSC2246).

ALTER TABLE local_media_repository
  ADD COLUMN unused_expires_at BIGINT DEFAULT NULL;

CREATE INDEX CONCURRENTLY ON local_media_repository (unused_expires_at);
