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

CREATE TABLE device_inbox (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    message_json TEXT NOT NULL -- {"type":, "sender":, "content",}
);

CREATE INDEX device_inbox_user_stream_id ON device_inbox(user_id, device_id, stream_id);
CREATE INDEX device_inbox_stream_id ON device_inbox(stream_id);
