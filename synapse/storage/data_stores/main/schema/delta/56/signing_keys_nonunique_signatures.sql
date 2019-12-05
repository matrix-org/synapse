/* Copyright 2019 The Matrix.org Foundation C.I.C.
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

/* The cross-signing signatures index should not be a unique index, because a
 * user may upload multiple signatures for the same target user. The previous
 * index was unique, so delete it if it's there and create a new non-unique
 * index. */

DROP INDEX IF EXISTS e2e_cross_signing_signatures_idx; CREATE INDEX IF NOT
EXISTS e2e_cross_signing_signatures2_idx ON e2e_cross_signing_signatures(user_id, target_user_id, target_device_id);
