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

angular.module('matrixFilter', [])

// Compute the room name according to information we have
.filter('mRoomName', ['$rootScope', 'matrixService', function($rootScope, matrixService) {
    return function(room_id) {
        var roomName;

        // If there is an alias, use it
        // TODO: only one alias is managed for now
        var alias = matrixService.getRoomIdToAliasMapping(room_id);
        if (alias) {
            roomName = alias;
        }

        if (undefined === roomName) {
            // Else, build the name from its users
            var room = $rootScope.events.rooms[room_id];
            if (room) {
                var room_name_event = room["m.room.name"];

                if (room_name_event) {
                    roomName = room_name_event.content.name;
                }
                else if (room.members) {
                    // Limit the room renaming to 1:1 room
                    if (2 === Object.keys(room.members).length) {
                        for (var i in room.members) {
                            var member = room.members[i];
                            if (member.state_key !== matrixService.config().user_id) {

                                if (member.state_key in $rootScope.presence) {
                                    // If the user is available in presence, use the displayname there
                                    // as it is the most uptodate
                                    roomName = $rootScope.presence[member.state_key].content.displayname;
                                }
                                else if (member.content.displayname) {
                                    roomName = member.content.displayname;
                                }
                                else {
                                    roomName = member.state_key;
                                }
                            }
                        }
                    }
                    else if (1 === Object.keys(room.members).length) {
                        // The other member may be in the invite list, get all invited users
                        var invitedUserIDs = [];
                        for (var i in room.messages) {
                            var message = room.messages[i];
                            if ("m.room.member" === message.type && "invite" === message.membership) {
                                // Make sure there is no duplicate user
                                if (-1 === invitedUserIDs.indexOf(message.state_key)) {
                                    invitedUserIDs.push(message.state_key);
                                }
                            } 
                        }
                        
                        // For now, only 1:1 room needs to be renamed. It means only 1 invited user
                        if (1 === invitedUserIDs.length) {
                            var userID = invitedUserIDs[0];

                            // Try to resolve his displayname in presence global data
                            if (userID in $rootScope.presence) {
                                roomName = $rootScope.presence[userID].content.displayname;
                            }
                            else {
                                roomName = userID;
                            }
                        }
                    }
                }
            }
        }

        if (undefined === roomName) {
            // By default, use the room ID
            roomName = room_id;
        }

        return roomName;
    };
}]);
