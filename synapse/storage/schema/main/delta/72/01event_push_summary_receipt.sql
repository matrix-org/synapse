/* Copyright 2022 The Matrix.org Foundation C.I.C
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

-- Add a column that records the position of the read receipt for the user at
-- the time we summarised the push actions. This is used to check if the counts
-- are up to date after a new read receipt has been sent.
--
-- Null means that we can skip that check, as the row was written by an older
-- version of Synapse that updated `event_push_summary` synchronously when
-- persisting a new read receipt
ALTER TABLE event_push_summary ADD COLUMN last_receipt_stream_ordering BIGINT;


-- Tracks which new receipts we've handled
CREATE TABLE event_push_summary_last_receipt_stream_id (
    Lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
    stream_id BIGINT NOT NULL,
    CHECK (Lock='X')
);

INSERT INTO event_push_summary_last_receipt_stream_id (stream_id)
  SELECT COALESCE(MAX(stream_id), 0)
  FROM receipts_linearized;
