/* Copyright 2018 New Vector Ltd
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

/*
 * Add a batch number to track changes to profiles and the
 * order they're made in so we can replicate user profiles
 * to other hosts as they change
 */
ALTER TABLE profiles ADD COLUMN batch BIGINT DEFAULT NULL;

/*
 * Index on the batch number so we can get profiles
 * by their batch
 */
CREATE INDEX profiles_batch_idx ON profiles(batch);

/*
 * A table to track what batch of user profiles has been
 * synced to what profile replication target.
 */
CREATE TABLE profile_replication_status (
    host TEXT NOT NULL,
    last_synced_batch BIGINT NOT NULL
);
