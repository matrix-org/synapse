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
.filter('orderRecents', ["matrixService", "eventHandlerService", function(matrixService, eventHandlerService) {
    return function(rooms) {
        var user_id = matrixService.config().user_id;

        // Transform the dict into an array
        // The key, room_id, is already in value objects
        var filtered = [];
        angular.forEach(rooms, function(room, room_id) {
            
            // Show the room only if the user has joined it or has been invited
            // (ie, do not show it if he has been banned)
            var member = eventHandlerService.getMember(room_id, user_id);
            if (member && ("invite" === member.membership || "join" === member.membership)) {
            
                // Count users here
                // TODO: Compute it directly in eventHandlerService
                room.numUsersInRoom = eventHandlerService.getUsersCountInRoom(room_id);

                filtered.push(room);
            }
            else if ("invite" === room.membership) {
                // The only information we have about the room is that the user has been invited
                filtered.push(room);
            }
        });

        // And time sort them
        // The room with the lastest message at first
        filtered.sort(function (roomA, roomB) {

            var lastMsgRoomA = eventHandlerService.getLastMessage(roomA.room_id, true);
            var lastMsgRoomB = eventHandlerService.getLastMessage(roomB.room_id, true);

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