/* Copyright 2014 matrix.org
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
CREATE TABLE IF NOT EXISTS context_edge_pdus(
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- twistar requires this
    pdu_id TEXT, 
    origin TEXT,
    context TEXT, 
    CONSTRAINT context_edge_pdu_id_origin UNIQUE (pdu_id, origin)
);

CREATE TABLE IF NOT EXISTS origin_edge_pdus(
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- twistar requires this
    pdu_id TEXT,
    origin TEXT,
    CONSTRAINT origin_edge_pdu_id_origin UNIQUE (pdu_id, origin)
);

CREATE INDEX IF NOT EXISTS context_edge_pdu_id ON context_edge_pdus(pdu_id, origin); 
CREATE INDEX IF NOT EXISTS origin_edge_pdu_id ON origin_edge_pdus(pdu_id, origin);
