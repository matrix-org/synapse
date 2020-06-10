/* Copyright 2015, 2016 OpenMarket Ltd
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

CREATE TABLE IF NOT EXISTS account_data(
    user_id TEXT NOT NULL,
    account_data_type TEXT NOT NULL, -- The type of the account_data.
    stream_id BIGINT NOT NULL, -- The version of the account_data.
    content TEXT NOT NULL,  -- The JSON content of the account_data
    CONSTRAINT account_data_uniqueness UNIQUE (user_id, account_data_type)
);


CREATE TABLE IF NOT EXISTS room_account_data(
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    account_data_type TEXT NOT NULL, -- The type of the account_data.
    stream_id BIGINT NOT NULL, -- The version of the account_data.
    content TEXT NOT NULL,  -- The JSON content of the account_data
    CONSTRAINT room_account_data_uniqueness UNIQUE (user_id, room_id, account_data_type)
);


CREATE INDEX account_data_stream_id on account_data(user_id, stream_id);
CREATE INDEX room_account_data_stream_id on room_account_data(user_id, stream_id);
