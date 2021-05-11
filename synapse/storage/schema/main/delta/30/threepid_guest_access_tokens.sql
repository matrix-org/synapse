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

-- Stores guest account access tokens generated for unbound 3pids.
CREATE TABLE threepid_guest_access_tokens(
    medium TEXT, -- The medium of the 3pid. Must be "email".
    address TEXT, -- The 3pid address.
    guest_access_token TEXT, -- The access token for a guest user for this 3pid.
    first_inviter TEXT -- User ID of the first user to invite this 3pid to a room.
);

CREATE UNIQUE INDEX threepid_guest_access_tokens_index ON threepid_guest_access_tokens(medium, address);
