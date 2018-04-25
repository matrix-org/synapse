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


CREATE TABLE user_daily_visits ( user_id TEXT NOT NULL,
                                 device_id TEXT,
                                 user_agent TEXT NOT NULL,
                                 timestamp BIGINT NOT NULL );

/* What indexes should I include?
 * Reads are offline so should optimise for writes
 * Need to check if already an entry so user,day
 */
