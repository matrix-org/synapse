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
// TODO: It would be nice if this was stateless and had no dependencies. That would
//       make the business logic here a lot easier to see.
.filter('mRoomName', ['$rootScope', 'matrixService', 'modelService', 'mUserDisplayNameFilter',
function($rootScope, matrixService, modelService, mUserDisplayNameFilter) {
    return function(room_id) {
        var roomName;

        // If there is an alias, use it
        // TODO: only one alias is managed for now
        var alias = modelService.getRoomIdToAliasMapping(room_id);
        var room = modelService.getRoom(room_id).current_room_state;
        
        var room_name_event = room.state("m.room.name");

        // Determine if it is a public room
        var isPublicRoom = false;
        if (room.state("m.room.join_rules") && room.state("m.room.join_rules").content) {
            isPublicRoom = ("public" === room.state("m.room.join_rules").content.join_rule);
        }
        
        if (room_name_event) {
            roomName = room_name_event.content.name;
        }
        else if (alias) {
            roomName = alias;
        }
        else if (Object.keys(room.members).length > 0 && !isPublicRoom) { // Do not rename public room
            var user_id = matrixService.config().user_id;
            
            // this is a "one to one" room and should have the name of the other user.
            if (Object.keys(room.members).length === 2) {
                for (var i in room.members) {
                    if (!room.members.hasOwnProperty(i)) continue;

                    var member = room.members[i].event;
                    if (member.state_key !== user_id) {
                        roomName = mUserDisplayNameFilter(member.state_key, room_id);
                        if (!roomName) {
                            roomName = member.state_key;
                        }
                        break;
                    }
                }
            }
            else if (Object.keys(room.members).length === 1) {
                // this could be just us (self-chat) or could be the other person
                // in a room if they have invited us to the room. Find out which.
                var otherUserId = Object.keys(room.members)[0];
                if (otherUserId === user_id) {
                    // it's us, we may have been invited to this room or it could
                    // be a self chat.
                    if (room.members[otherUserId].event.content.membership === "invite") {
                        // someone invited us, use the right ID.
                        roomName = mUserDisplayNameFilter(room.members[otherUserId].event.user_id, room_id);
                        if (!roomName) {
                            roomName = room.members[otherUserId].event.user_id;
                        }
                    }
                    else {
                        roomName = mUserDisplayNameFilter(otherUserId, room_id);
                        if (!roomName) {
                            roomName = user_id;
                        }
                    }
                }
                else { // it isn't us, so use their name if we know it.
                    roomName = mUserDisplayNameFilter(otherUserId, room_id);
                    if (!roomName) {
                        roomName = otherUserId;
                    }
                }
            }
            else if (Object.keys(room.members).length === 0) {
                // this shouldn't be possible
                console.error("0 members in room >> " + room_id);
            }
        }
        

        // Always show the alias in the room displayed name
        if (roomName && alias && alias !== roomName) {
            roomName += " (" + alias + ")";
        }

        if (undefined === roomName) {
            // By default, use the room ID
            roomName = room_id;
        }

        return roomName;
    };
}])

// Return the user display name
.filter('mUserDisplayName', ['modelService', 'matrixService', function(modelService, matrixService) {
    /**
     * Return the display name of an user acccording to data already downloaded
     * @param {String} user_id the id of the user
     * @param {String} room_id the room id
     * @param {boolean} wrap whether to insert whitespace into the userid (if displayname not available) to help it wrap
     * @returns {String} A suitable display name for the user.
     */
    return function(user_id, room_id, wrap) {
        var displayName;

        // Get the user display name from the member list of the room
        var member = modelService.getMember(room_id, user_id);
        if (member) {
            member = member.event;
        }
        if (member && member.content.displayname) { // Do not consider null displayname
            displayName = member.content.displayname;

            // Disambiguate users who have the same displayname in the room
            if (user_id !== matrixService.config().user_id) {
                var room = modelService.getRoom(room_id);

                for (var member_id in room.current_room_state.members) {
                    if (room.current_room_state.members.hasOwnProperty(member_id) && member_id !== user_id) {
                        var member2 = room.current_room_state.members[member_id].event;
                        if (member2.content.displayname && member2.content.displayname === displayName) {
                            displayName = displayName + " (" + user_id + ")";
                            break;
                        }
                    }
                }
            }
        }

        // The user may not have joined the room yet. So try to resolve display name from presence data
        // Note: This data may not be available
        if (undefined === displayName) {
            var usr = modelService.getUser(user_id);
            if (usr) {
                displayName = usr.event.content.displayname;
            }
        }

        if (undefined === displayName) {
            // By default, use the user ID
            if (wrap && user_id.indexOf(':') >= 0) {
                displayName = user_id.substr(0, user_id.indexOf(':')) + " " + user_id.substr(user_id.indexOf(':'));
            }
            else {
                displayName = user_id;
            }
        }
        
        return displayName;
    };
}]);
