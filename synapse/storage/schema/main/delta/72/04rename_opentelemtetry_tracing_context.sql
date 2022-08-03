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

-- Rename to generalized `tracing_context` since we're moving from opentracing to opentelemetry
ALTER TABLE device_lists_outbound_pokes RENAME COLUMN opentracing_context TO tracing_context;
ALTER TABLE device_lists_changes_in_room RENAME COLUMN opentracing_context TO tracing_context;
