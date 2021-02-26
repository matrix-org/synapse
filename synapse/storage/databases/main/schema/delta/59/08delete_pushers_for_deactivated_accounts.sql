/* Copyright 2021 The Matrix.org Foundation C.I.C
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


-- We may not have deleted all pushers for deactivated accounts. Do so now.
--
-- Note: We don't bother updating the `deleted_pushers` table as it's just use
-- to stop pushers on workers, and that will happen when they get next restarted.
DELETE FROM pushers WHERE user_name IN (SELECT name FROM users WHERE deactivated = 1);
