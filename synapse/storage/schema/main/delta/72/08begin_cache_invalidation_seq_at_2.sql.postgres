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
 

-- The sequence needs to begin at 2 because a bunch of code assumes that
-- get_next_id_txn will return values >= 2, cf this comment:
-- https://github.com/matrix-org/synapse/blob/b93bd95e8ab64d27ae26841020f62ee61272a5f2/synapse/storage/util/id_generators.py#L344

SELECT setval('cache_invalidation_stream_seq', (
    SELECT COALESCE(MAX(last_value), 1) FROM cache_invalidation_stream_seq
));
