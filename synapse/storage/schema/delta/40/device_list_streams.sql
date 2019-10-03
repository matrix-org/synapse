/* Copyright 2017 OpenMarket Ltd
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

-- Cache of remote devices.
CREATE TABLE device_lists_remote_cache (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    content TEXT NOT NULL
);

-- The last update we got for a user. Empty if we're not receiving updates for
-- that user.
CREATE TABLE device_lists_remote_extremeties (
    user_id TEXT NOT NULL,
    stream_id TEXT NOT NULL
);

-- we used to create non-unique indexes on these tables, but as of update 52 we create
-- unique indexes concurrently:
--
-- CREATE INDEX device_lists_remote_cache_id ON device_lists_remote_cache(user_id, device_id);
-- CREATE INDEX device_lists_remote_extremeties_id ON device_lists_remote_extremeties(user_id, stream_id);


-- Stream of device lists updates. Includes both local and remotes
CREATE TABLE device_lists_stream (
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL
);

CREATE INDEX device_lists_stream_id ON device_lists_stream(stream_id, user_id);


-- The stream of updates to send to other servers. We keep at least one row
-- per user that was sent so that the prev_id for any new updates can be
-- calculated
CREATE TABLE device_lists_outbound_pokes (
    destination TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    sent BOOLEAN NOT NULL,
    ts BIGINT NOT NULL  -- So that in future we can clear out pokes to dead servers
);

CREATE INDEX device_lists_outbound_pokes_id ON device_lists_outbound_pokes(destination, stream_id);
CREATE INDEX device_lists_outbound_pokes_user ON device_lists_outbound_pokes(destination, user_id);
