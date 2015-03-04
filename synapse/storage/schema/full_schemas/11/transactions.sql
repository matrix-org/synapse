/* Copyright 2014, 2015 OpenMarket Ltd
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
-- Stores what transaction ids we have received and what our response was
CREATE TABLE IF NOT EXISTS received_transactions(
    transaction_id TEXT, 
    origin TEXT, 
    ts INTEGER,
    response_code INTEGER,
    response_json TEXT,
    has_been_referenced BOOL default 0, -- Whether thishas been referenced by a prev_tx
    CONSTRAINT uniquesss UNIQUE (transaction_id, origin) ON CONFLICT REPLACE
);

CREATE UNIQUE INDEX IF NOT EXISTS transactions_txid ON received_transactions(transaction_id, origin);
CREATE INDEX IF NOT EXISTS transactions_have_ref ON received_transactions(origin, has_been_referenced);-- WHERE has_been_referenced = 0;


-- Stores what transactions we've sent, what their response was (if we got one) and whether we have
-- since referenced the transaction in another outgoing transaction
CREATE TABLE IF NOT EXISTS sent_transactions(
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- This is used to apply insertion ordering
    transaction_id TEXT,
    destination TEXT,
    response_code INTEGER DEFAULT 0,
    response_json TEXT,
    ts INTEGER
);

CREATE INDEX IF NOT EXISTS sent_transaction_dest ON sent_transactions(destination);
CREATE INDEX IF NOT EXISTS sent_transaction_dest_referenced ON sent_transactions(
    destination
);
CREATE INDEX IF NOT EXISTS sent_transaction_txn_id ON sent_transactions(transaction_id);
-- So that we can do an efficient look up of all transactions that have yet to be successfully
-- sent.
CREATE INDEX IF NOT EXISTS sent_transaction_sent ON sent_transactions(response_code);


-- For sent transactions only.
CREATE TABLE IF NOT EXISTS transaction_id_to_pdu(
    transaction_id INTEGER,
    destination TEXT,
    pdu_id TEXT,
    pdu_origin TEXT
);

CREATE INDEX IF NOT EXISTS transaction_id_to_pdu_tx ON transaction_id_to_pdu(transaction_id, destination);
CREATE INDEX IF NOT EXISTS transaction_id_to_pdu_dest ON transaction_id_to_pdu(destination);
CREATE INDEX IF NOT EXISTS transaction_id_to_pdu_index ON transaction_id_to_pdu(transaction_id, destination);

-- To track destination health
CREATE TABLE IF NOT EXISTS destinations(
    destination TEXT PRIMARY KEY,
    retry_last_ts INTEGER,
    retry_interval INTEGER
);
