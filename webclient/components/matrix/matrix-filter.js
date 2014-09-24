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
.filter('mRoomName', ['$rootScope', 'matrixService', 'eventHandlerService', function($rootScope, matrixService, eventHandlerService) {
    return function(room_id) {
        var roomName;

        // If there is an alias, use it
        // TODO: only one alias is managed for now
        var alias = matrixService.getRoomIdToAliasMapping(room_id);

        var room = $rootScope.events.rooms[room_id];
        if (room) {
            // Get name from room state date
            var room_name_event = room["m.room.name"];
            if (room_name_event) {
                roomName = room_name_event.content.name;
            }
            else if (alias) {
                roomName = alias;
            }
            else if (room.members) {

                var user_id = matrixService.config().user_id;

                // Else, build the name from its users
                // Limit the room renaming to 1:1 room
                if (2 === Object.keys(room.members).length) {
                    for (var i in room.members) {
                        var member = room.members[i];
                        if (member.state_key !== user_id) {
                            roomName = eventHandlerService.getUserDisplayName(room_id, member.state_key);
                            break;
                        }
                    }
                }
                else if (Object.keys(room.members).length <= 1) {
                    
                    var otherUserId;

                    if (Object.keys(room.members)[0] && Object.keys(room.members)[0] !== user_id) {
                        otherUserId = Object.keys(room.members)[0];
                    }
                    else {
                        // it's got to be an invite, or failing that a self-chat;
                        otherUserId = room.inviter || user_id;
/*                        
                        // XXX: This should all be unnecessary now thanks to using the /rooms/<room>/roomid API

                        // The other member may be in the invite list, get all invited users
                        var invitedUserIDs = [];
                        
                        // XXX: *SURELY* we shouldn't have to trawl through the whole messages list to
                        // find invite - surely the other user should be in room.members with state invited? :/ --Matthew
                        for (var i in room.messages) {
                            var message = room.messages[i];
                            if ("m.room.member" === message.type && "invite" === message.content.membership) {
                                // Filter out the current user
                                var member_id = message.state_key;
                                if (member_id === user_id) {
                                    member_id = message.user_id;
                                }
                                if (member_id !== user_id) {
                                    // Make sure there is no duplicate user
                                    if (-1 === invitedUserIDs.indexOf(member_id)) {
                                        invitedUserIDs.push(member_id);
                                    }
                                }
                            } 
                        }

                        // For now, only 1:1 room needs to be renamed. It means only 1 invited user
                        if (1 === invitedUserIDs.length) {
                            otherUserId = invitedUserIDs[0];
                        }
*/                        
                    }
                    
                    // Get the user display name
                    roomName = eventHandlerService.getUserDisplayName(room_id, otherUserId);
                }
            }
        }

        // Always show the alias in the room displayed name
        if (roomName && alias && alias !== roomName) {
            roomName += " (" + alias + ")";
        }

        if (undefined === roomName) {
            // By default, use the room ID
            roomName = room_id;

            // XXX: this is *INCREDIBLY* heavy logging for a function that calls every single
            // time any kind of digest runs which refreshes a room name...
            // commenting it out for now.

            // Log some information that lead to this leak
            // console.log("Room ID leak for " + room_id);
            // console.log("room object: " + JSON.stringify(room, undefined, 4));   
        }

        return roomName;
    };
}])

// Return the user display name
.filter('mUserDisplayName', ['eventHandlerService', function(eventHandlerService) {
    return function(user_id, room_id) {
        return eventHandlerService.getUserDisplayName(room_id, user_id);
    };
}]);
