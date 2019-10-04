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
 * Store any accounts that have been requested to be deactivated.
 * We part the account from all the rooms its in when its
 * deactivated. This can take some time and synapse may be restarted
 * before it completes, so store the user IDs here until the process
 * is complete.
 */
CREATE TABLE users_pending_deactivation (
    user_id TEXT NOT NULL
);
