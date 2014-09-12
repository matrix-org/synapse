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

angular.module('RecentsController', ['matrixService', 'matrixFilter', 'eventHandlerService'])
.controller('RecentsController', ['$rootScope', '$scope', 'matrixService', 'eventHandlerService', 
                               function($rootScope, $scope, matrixService, eventHandlerService) {
                                   
    // FIXME: Angularjs reloads the controller (and resets its $scope) each time
    // the page URL changes, use $rootScope to avoid to have to reload data
    $rootScope.rooms;

    // $rootScope of the parent where the recents component is included can override this value
    // in order to highlight a specific room in the list
    $rootScope.recentsSelectedRoomID;
    
    var listenToEventStream = function() {
        // Refresh the list on matrix invitation and message event
        $rootScope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                if (!$rootScope.rooms[event.room_id]) {
                    // The user has joined a new room, which we do not have data yet. The reason is that
                    // the room has appeared in the scope of the user rooms after the global initialSync
                    // FIXME: an initialSync on this specific room should be done
                    $rootScope.rooms[event.room_id] = {
                        room_id:event.room_id
                    };
                }
                else if (event.state_key === matrixService.config().user_id && "invite" !== event.membership && "join" !== event.membership) {
                    // The user has been kicked or banned from the room, remove this room from the recents
                    delete $rootScope.rooms[event.room_id];
                }
                
                if ($rootScope.rooms[event.room_id]) {
                    $rootScope.rooms[event.room_id].lastMsg = event;
                }
                
                // Update room users count
                $rootScope.rooms[event.room_id].numUsersInRoom = getUsersCountInRoom(event.room_id);
            }
        });
        $rootScope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $rootScope.rooms[event.room_id].lastMsg = event;              
            }
        });
        $rootScope.$on(eventHandlerService.CALL_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $rootScope.rooms[event.room_id].lastMsg = event;
            }
        });
        $rootScope.$on(eventHandlerService.ROOM_CREATE_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $rootScope.rooms[event.room_id] = event;
            }
        });
        $rootScope.$on(eventHandlerService.NAME_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $rootScope.rooms[event.room_id].lastMsg = event;
            }
        });
        $rootScope.$on(eventHandlerService.TOPIC_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $rootScope.rooms[event.room_id].lastMsg = event;
            }
        });
    };
    
    /**
     * Compute the room users number, ie the number of members who has joined the room.
     * @param {String} room_id the room id
     * @returns {undefined | Number} the room users number if available
     */
    var getUsersCountInRoom = function(room_id) {
        var memberCount;
        
        var room = $rootScope.events.rooms[room_id];
        if (room) {
            memberCount = 0;
            
            for (var i in room.members) {
                var member = room.members[i];
                
                if ("join" === member.membership) {
                    memberCount = memberCount + 1;
                }
            }
        }
        
        return memberCount;
    };

    $scope.onInit = function() {
        // Init recents list only once
        if ($rootScope.rooms) {
            return;
        }
        
        $rootScope.rooms = {};
        
        // Use initialSync data to init the recents list
        eventHandlerService.waitForInitialSyncCompletion().then(
            function(initialSyncData) {
            
                var rooms = initialSyncData.data.rooms;
                for (var i=0; i<rooms.length; i++) {
                    var room = rooms[i];
                    
                    // Add room_alias & room_display_name members
                    $rootScope.rooms[room.room_id] = angular.extend(room, matrixService.getRoomAliasAndDisplayName(room));

                    // Create a shortcut for the last message of this room
                    if (room.messages && room.messages.chunk && room.messages.chunk[0]) {
                        $rootScope.rooms[room.room_id].lastMsg = room.messages.chunk[0];
                    }
                    
                    $rootScope.rooms[room.room_id].numUsersInRoom = getUsersCountInRoom(room.room_id);
                }

                // From now, update recents from the stream
                listenToEventStream();
            },
            function(error) {
                $rootScope.feedback = "Failure: " + error.data;
            }
        );
    };

    // Clean data when user logs out
    $scope.$on(eventHandlerService.RESET_EVENT, function() {

        delete $rootScope.rooms;
    });
}]);

