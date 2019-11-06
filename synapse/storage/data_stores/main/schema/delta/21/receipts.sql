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


CREATE TABLE IF NOT EXISTS receipts_graph(
    room_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    data TEXT NOT NULL,
    CONSTRAINT receipts_graph_uniqueness UNIQUE (room_id, receipt_type, user_id)
);

CREATE TABLE IF NOT EXISTS receipts_linearized (
    stream_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    data TEXT NOT NULL,
    CONSTRAINT receipts_linearized_uniqueness UNIQUE (room_id, receipt_type, user_id)
);

CREATE INDEX receipts_linearized_id ON receipts_linearized(
  stream_id
);
