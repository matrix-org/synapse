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

 CREATE TABLE federation_stream_position(
     type TEXT NOT NULL,
     stream_id INTEGER NOT NULL
 );

 INSERT INTO federation_stream_position (type, stream_id) VALUES ('federation', -1);
 INSERT INTO federation_stream_position (type, stream_id) SELECT 'events', coalesce(max(stream_ordering), -1) FROM events;
