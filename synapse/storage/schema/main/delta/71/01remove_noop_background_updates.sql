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

-- Clean-up background updates which should no longer be run. Previously these
-- used the (now removed) register_noop_background_update method.

-- Used to be a background update that deletes all device_inboxes for deleted
-- devices.
DELETE FROM background_updates WHERE update_name = 'remove_deleted_devices_from_device_inbox';
-- Used to be a background update that deletes all device_inboxes for hidden
-- devices.
DELETE FROM background_updates WHERE update_name = 'remove_hidden_devices_from_device_inbox';

-- A pair of background updates that were added during the 1.14 release cycle,
-- but replaced with 58/06dlols_unique_idx.py
DELETE FROM background_updates WHERE update_name = 'device_lists_outbound_last_success_unique_idx';
DELETE FROM background_updates WHERE update_name = 'drop_device_lists_outbound_last_success_non_unique_idx';

-- The event_thread_relation background update was replaced with the
-- event_arbitrary_relations one, which handles any relation to avoid
-- needed to potentially crawl the entire events table in the future.
DELETE FROM background_updates WHERE update_name = 'event_thread_relation';

-- A legacy groups background update.
DELETE FROM background_updates WHERE update_name = 'local_group_updates_index';

-- The original impl of _drop_media_index_without_method was broken (see
-- https://github.com/matrix-org/synapse/issues/8649), so we replace the original
-- impl with a no-op and run the fixed migration as
-- media_repository_drop_index_wo_method_2.
DELETE FROM background_updates WHERE update_name = 'media_repository_drop_index_wo_method';

-- We no longer use refresh tokens, but it's possible that some people
-- might have a background update queued to build this index. Just
-- clear the background update.
DELETE FROM background_updates WHERE update_name = 'refresh_tokens_device_index';

DELETE FROM background_updates WHERE update_name = 'user_threepids_grandfather';

-- We used to have a background update to turn the GIN index into a
-- GIST one; we no longer do that (obviously) because we actually want
-- a GIN index. However, it's possible that some people might still have
-- the background update queued, so we register a handler to clear the
-- background update.
DELETE FROM background_updates WHERE update_name = 'event_search_postgres_gist';

-- We no longer need to perform clean-up.
DELETE FROM background_updates WHERE update_name = 'populate_stats_cleanup';
DELETE FROM background_updates WHERE update_name = 'populate_stats_prepare';
