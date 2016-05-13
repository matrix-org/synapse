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


-- The following indices are redundant, other indices are equivalent or
-- supersets
DROP INDEX IF EXISTS events_room_id;
DROP INDEX IF EXISTS events_order;
DROP INDEX IF EXISTS events_topological_ordering;
DROP INDEX IF EXISTS events_stream_ordering;
DROP INDEX IF EXISTS state_groups_id;
DROP INDEX IF EXISTS event_to_state_groups_id;
DROP INDEX IF EXISTS event_push_actions_room_id_event_id_user_id_profile_tag;
DROP INDEX IF EXISTS event_push_actions_room_id_user_id;

DROP INDEX IF EXISTS event_destinations_id;
DROP INDEX IF EXISTS st_extrem_id;
DROP INDEX IF EXISTS event_content_hashes_id;
DROP INDEX IF EXISTS event_signatures_id;
DROP INDEX IF EXISTS event_edge_hashes_id;
DROP INDEX IF EXISTS redactions_event_id;
DROP INDEX IF EXISTS remote_media_cache_thumbnails_media_id;
DROP INDEX IF EXISTS room_hosts_room_id;
DROP INDEX IF EXISTS event_search_ev_ridx;


-- The following indices were unused
DROP INDEX IF EXISTS evauth_edges_auth_id;
DROP INDEX IF EXISTS topics_room_id;
DROP INDEX IF EXISTS presence_stream_state;
