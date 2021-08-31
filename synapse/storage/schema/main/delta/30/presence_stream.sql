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


 CREATE TABLE presence_stream(
     stream_id BIGINT,
     user_id TEXT,
     state TEXT,
     last_active_ts BIGINT,
     last_federation_update_ts BIGINT,
     last_user_sync_ts BIGINT,
     status_msg TEXT,
     currently_active BOOLEAN
 );

 CREATE INDEX presence_stream_id ON presence_stream(stream_id, user_id);
 CREATE INDEX presence_stream_user_id ON presence_stream(user_id);
 CREATE INDEX presence_stream_state ON presence_stream(state);
