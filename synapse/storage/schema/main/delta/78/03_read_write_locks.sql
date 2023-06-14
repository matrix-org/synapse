/* Copyright 2023 The Matrix.org Foundation C.I.C
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


-- We implement read/write style locks by using two tables with mutual foreign
-- key constraints. Note that this implementation is vulnerable to starving
-- writers if read locks repeatedly get acquired.
--
-- The first table (`worker_read_write_locks_mode`) indicates that a given lock
-- has either been acquired in read mode *or* write mode, but not both. This is
-- enforced by the unique constraint. Each instance of a lock being acquired is
-- associated with a random `token`.
--
-- The second table (`worker_read_write_locks`) tracks who has currently
-- acquired a given lock. It ensures that a lock can only be acquired once in
-- write mode by using unique constraints.
--
-- The foreign key from the second to first table enforces that for any given
-- lock the second table cannot have a mix of rows with read or write.
--
-- The foreign key from the first to second table enforces that we don't have a
-- row for a lock in the first table if not in the second table. (Only supported
-- on PostgreSQL).
--
--
-- Furthermore, we add some triggers to automatically keep the first table up to
-- date when inserting/deleting from the second table. This reduces the number
-- of round trips needed to acquire and release locks, as those operations
-- simply become an INSERT or DELETE. These triggers are added in a separate
-- delta due to database specific syntax.


-- A table to track whether a lock is currently acquired, and if so whether its
-- in read or write mode.
CREATE TABLE worker_read_write_locks_mode (
    lock_name TEXT NOT NULL,
    lock_key TEXT NOT NULL,
    -- Whether this lock is in read (false) or write (true) mode
    write_lock BOOLEAN NOT NULL,
    -- A token that has currently acquired the lock. We need this so that we can
    -- add a foreign constraint from this table to `worker_read_write_locks`.
    token TEXT NOT NULL
);

-- Ensure that we can only have one row per lock
CREATE UNIQUE INDEX worker_read_write_locks_mode_key ON worker_read_write_locks_mode (lock_name, lock_key);
-- We need this (redundant) constraint so that we can have a foreign key
-- constraint against this table.
CREATE UNIQUE INDEX worker_read_write_locks_mode_type ON worker_read_write_locks_mode (lock_name, lock_key, write_lock);


-- A table to track who has currently acquired a given lock.
CREATE TABLE worker_read_write_locks (
    lock_name TEXT NOT NULL,
    lock_key TEXT NOT NULL,
    -- We write the instance name to ease manual debugging, we don't ever read
    -- from it.
    -- Note: instance names aren't guarenteed to be unique.
    instance_name TEXT NOT NULL,
    -- A token that has currently acquired the lock. We need this so that we can
    -- add a foreign constraint from this table to `worker_read_write_locks`.
    write_lock BOOLEAN NOT NULL,
    -- A random string generated each time an instance takes out a lock. Used by
    -- the instance to tell whether the lock is still held by it (e.g. in the
    -- case where the process stalls for a long time the lock may time out and
    -- be taken out by another instance, at which point the original instance
    -- can tell it no longer holds the lock as the tokens no longer match).
    token TEXT NOT NULL,
    last_renewed_ts BIGINT NOT NULL,

    -- This constraint ensures that a given lock has only been acquired in read
    -- xor write mode, but not both.
    FOREIGN KEY (lock_name, lock_key, write_lock) REFERENCES worker_read_write_locks_mode (lock_name, lock_key, write_lock)
);

CREATE UNIQUE INDEX worker_read_write_locks_key ON worker_read_write_locks (lock_name, lock_key, token);
-- Ensures that only one instance can acquire a lock in write mode at a time.
CREATE UNIQUE INDEX worker_read_write_locks_write ON worker_read_write_locks (lock_name, lock_key) WHERE write_lock;
