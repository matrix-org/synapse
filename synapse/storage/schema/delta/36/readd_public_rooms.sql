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


INSERT INTO public_room_list_stream (stream_id, room_id, visibility)
    SELECT 1, room_id, is_public FROM rooms AS r
    WHERE is_public = CAST(1 AS BOOLEAN)
    AND NOT EXISTS (
        SELECT room_id FROM stream_ordering_to_exterm WHERE room_id = r.room_id
    );
