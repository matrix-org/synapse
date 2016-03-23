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


/* This release removes the restriction that published rooms must have an alias,
 * so we go back and ensure the only 'public' rooms are ones with an alias.
 * We use (1 = 0) and (1 = 1) so that it works in both postgres and sqlite
 */
UPDATE rooms SET is_public = (1 = 0) WHERE is_public = (1 = 1) AND room_id not in (
    SELECT room_id FROM room_aliases
);
