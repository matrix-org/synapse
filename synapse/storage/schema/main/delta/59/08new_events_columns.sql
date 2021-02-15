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

ALTER TABLE events ADD COLUMN internal_metadata TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN json TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN format_version INTEGER;
ALTER TABLE events ADD COLUMN state_key TEXT;
ALTER TABLE events ADD COLUMN rejection_reason TEXT;

/*
for s in `seq -240000 10000 7530000`; do
    date; echo $s;
    psql synapse -c "update events e set json=ej.json, internal_metadata=ej.internal_metadata, format_version=ej.format_version, state_key = se.state_key, rejection_reason=rej.reason
    from event_json ej left join state_events se using (event_id) left join rejections rej using (event_id) where ej.event_id=e.event_id and e.stream_ordering between $s and ($s+9999)";
done
*/

