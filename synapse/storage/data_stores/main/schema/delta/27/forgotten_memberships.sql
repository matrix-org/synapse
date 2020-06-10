/* Copyright 2015, 2016 OpenMarket Ltd
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
 * Keeps track of what rooms users have left and don't want to be able to
 * access again.
 *
 * If all users on this server have left a room, we can delete the room
 * entirely.
 *
 * This column should always contain either 0 or 1.
 */

 ALTER TABLE room_memberships ADD COLUMN forgotten INTEGER DEFAULT 0;
