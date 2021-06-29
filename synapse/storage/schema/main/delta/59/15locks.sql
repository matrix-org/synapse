/* Copyright 2021 The Matrix.org Foundation C.I.C
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


-- A noddy implementation of a distributed lock across workers. While a worker
-- has taken a lock out they should regularly update the `last_renewed_ts`
-- column, a lock will be considered dropped if `last_renewed_ts` is from ages
-- ago.
CREATE TABLE worker_locks (
    lock_name TEXT NOT NULL,
    lock_key TEXT NOT NULL,
    -- We write the instance name to ease manual debugging, we don't ever read
    -- from it.
    -- Note: instance names aren't guarenteed to be unique.
    instance_name TEXT NOT NULL,
    -- A random string generated each time an instance takes out a lock. Used by
    -- the instance to tell whether the lock is still held by it (e.g. in the
    -- case where the process stalls for a long time the lock may time out and
    -- be taken out by another instance, at which point the original instance
    -- can tell it no longer holds the lock as the tokens no longer match).
    token TEXT NOT NULL,
    last_renewed_ts BIGINT NOT NULL
);

CREATE UNIQUE INDEX worker_locks_key ON worker_locks (lock_name, lock_key);
