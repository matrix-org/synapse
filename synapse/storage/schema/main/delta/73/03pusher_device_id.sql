/* Copyright 2022 The Matrix.org Foundation C.I.C
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

-- Add a device_id column to track the device ID that created the pusher. It's NULLable
-- on purpose, because a) it might not be possible to track down the device that created
-- old pushers (pushers.access_token and access_tokens.device_id are both NULLable), and
-- b) access tokens retrieved via the admin API don't have a device associated to them.
ALTER TABLE pushers ADD COLUMN device_id TEXT;