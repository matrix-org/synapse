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
 * A flag saying whether the user owning the profile has been deactivated
 * This really belongs on the users table, not here, but the users table
 * stores users by their full user_id and profiles stores them by localpart,
 * so we can't easily join between the two tables. Plus, the batch number
 * realy ought to represent data in this table that has changed.
 */
ALTER TABLE profiles ADD COLUMN active SMALLINT DEFAULT 1 NOT NULL;
