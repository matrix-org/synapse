/* Copyright 2016 OpenMarket Ltd
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

/** Using CREATE INDEX directly is deprecated in favour of using background
 * update see synapse/storage/schema/delta/33/access_tokens_device_index.sql
 * and synapse/storage/registration.py for an example using
 * "access_tokens_device_index" **/
 CREATE INDEX event_push_actions_stream_ordering on event_push_actions(
     stream_ordering, user_id
 );
