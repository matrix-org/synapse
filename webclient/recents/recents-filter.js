/*
 Copyright 2014 OpenMarket Ltd
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

'use strict';

angular.module('RecentsController')
.filter('orderRecents', ["eventHandlerService", function(eventHandlerService) {
    return function(rooms) {

        // Transform the dict into an array
        // The key, room_id, is already in value objects
        var filtered = [];
        angular.forEach(rooms, function(room, room_id) {

            // Count users here
            // TODO: Compute it directly in eventHandlerService
            room.numUsersInRoom = eventHandlerService.getUsersCountInRoom(room_id);

            filtered.push(room);
        });

        // And time sort them
        // The room with the lastest message at first
        filtered.sort(function (roomA, roomB) {
            var lastMsgRoomA, lastMsgRoomB;

            if (roomA.messages && 0 < roomA.messages.length) {
                lastMsgRoomA = roomA.messages[roomA.messages.length - 1];
            }
            if (roomB.messages && 0 < roomB.messages.length) {
                lastMsgRoomB = roomB.messages[roomB.messages.length - 1];
            }

            // Invite message does not have a body message nor ts
            // Puth them at the top of the list
            if (undefined === lastMsgRoomA) {
                return -1;
            }
            else if (undefined === lastMsgRoomB) {
                return 1;
            }
            else {
                return lastMsgRoomB.ts - lastMsgRoomA.ts;
            }
        });
        return filtered;
    };
}]);