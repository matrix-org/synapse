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

            var room = $rootScope.events.rooms[room_id];
            if (room) {
                // Get name from room state date
                var room_name_event = room["m.room.name"];
                if (room_name_event) {
                    roomName = room_name_event.content.name;
                }
                else if (room.members) {
                    // Else, build the name from its users
                    // FIXME: Is it still required?
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
}])

// Compute the user display name in a room according to the data already downloaded
.filter('mUserDisplayName', ['$rootScope', function($rootScope) {
    return function(user_id, room_id) {
        var displayName;
    
        // Try to find the user name among presence data
        // Warning: that means we have received before a presence event for this
        // user which cannot be guaranted.
        // However, if we get the info by this way, we are sure this is the latest user display name
        // See FIXME comment below
        if (user_id in $rootScope.presence) {
            displayName = $rootScope.presence[user_id].content.displayname;
        }
            
        // FIXME: Would like to use the display name as defined in room members of the room.
        // But this information is the display name of the user when he has joined the room.
        // It does not take into account user display name update
        if (room_id) {
            var room = $rootScope.events.rooms[room_id];
            if (room && (user_id in room.members)) {
                var member = room.members[user_id];
                if (member.content.displayname) {
                    displayName = member.content.displayname;
                }
            }
        }
        
        if (undefined === displayName) {
            // By default, use the user ID
            displayName = user_id;
        }
        return displayName;
    };
}]);
