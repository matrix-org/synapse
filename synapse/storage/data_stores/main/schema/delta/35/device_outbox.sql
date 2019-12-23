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

DROP TABLE IF EXISTS device_federation_outbox;
CREATE TABLE device_federation_outbox (
    destination TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    queued_ts BIGINT NOT NULL,
    messages_json TEXT NOT NULL
);


DROP INDEX IF EXISTS device_federation_outbox_destination_id;
CREATE INDEX device_federation_outbox_destination_id
    ON device_federation_outbox(destination, stream_id);


DROP TABLE IF EXISTS device_federation_inbox;
CREATE TABLE device_federation_inbox (
    origin TEXT NOT NULL,
    message_id TEXT NOT NULL,
    received_ts BIGINT NOT NULL
);

DROP INDEX IF EXISTS device_federation_inbox_sender_id;
CREATE INDEX device_federation_inbox_sender_id
    ON device_federation_inbox(origin, message_id);
