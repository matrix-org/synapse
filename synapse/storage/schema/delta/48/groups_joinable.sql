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

/* 
 * This isn't a real ENUM because sqlite doesn't support it
 * and we use a default of NULL for inserted rows and interpret
 * NULL at the python store level as necessary so that existing
 * rows are given the correct default policy.
 */
ALTER TABLE groups ADD COLUMN join_policy TEXT NOT NULL DEFAULT 'invite';
