/* Copyright 2019 New Vector Ltd
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

-- we need to do this first due to foreign constraints
DROP TABLE IF EXISTS application_services_regex;

DROP TABLE IF EXISTS application_services;
DROP TABLE IF EXISTS transaction_id_to_pdu;
DROP TABLE IF EXISTS stats_reporting;
DROP TABLE IF EXISTS current_state_resets;
DROP TABLE IF EXISTS event_content_hashes;
DROP TABLE IF EXISTS event_destinations;
DROP TABLE IF EXISTS event_edge_hashes;
DROP TABLE IF EXISTS event_signatures;
DROP TABLE IF EXISTS feedback;
DROP TABLE IF EXISTS room_hosts;
DROP TABLE IF EXISTS server_tls_certificates;
DROP TABLE IF EXISTS state_forward_extremities;
