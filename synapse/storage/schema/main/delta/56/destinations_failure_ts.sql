/* Copyright 2019 The Matrix.org Foundation C.I.C
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
 * Record the timestamp when a given server started failing
 */
ALTER TABLE destinations ADD failure_ts BIGINT;

/* as a rough approximation, we assume that the server started failing at
 * retry_interval before the last retry
 */
UPDATE destinations SET failure_ts = retry_last_ts - retry_interval
    WHERE retry_last_ts > 0;
