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

-- Records when we see a "gap in the timeline", due to missing events over
-- federation. We record this so that we can tell clients there is a gap (by
-- marking the timeline section of a sync request as limited).
CREATE TABLE IF NOT EXISTS timeline_gaps (
    room_id TEXT NOT NULL,
    instance_name TEXT NOT NULL,
    stream_ordering BIGINT NOT NULL
);

CREATE INDEX timeline_gaps_room_id ON timeline_gaps(room_id, stream_ordering);
