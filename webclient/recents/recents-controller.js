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

// XXX FIXME TODO
// We should NOT be dumping things into $rootScope!!!! We should NOT be
// making any requests here, and should READ what is already in the 
// rootScope from the event handler service!!!
// XXX FIXME TODO

angular.module('RecentsController', ['matrixService', 'matrixFilter', 'eventHandlerService'])
.controller('RecentsController', ['$rootScope', '$scope', 'matrixService', 'eventHandlerService', 
                               function($rootScope, $scope, matrixService, eventHandlerService) {
                                   
    // FIXME: Angularjs reloads the controller (and resets its $scope) each time
    // the page URL changes, use $rootScope to avoid to have to reload data
    $rootScope.rooms;

    // $rootScope of the parent where the recents component is included can override this value
    // in order to highlight a specific room in the list
    $rootScope.recentsSelectedRoomID;

    // XXX FIXME TODO : We should NOT be doing this here, which could be
    // repeated for every controller instance. We should be doing this in
    // event handler service instead. In additon, this will break if there
    // isn't a recents controller visible when the last message comes in :/
    
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
    };
    

    $scope.onInit = function() {
        // Init recents list only once
        if ($rootScope.rooms) {
            return;
        }
        
        // XXX FIXME TODO
        // We should NOT be dumping things into $rootScope!!!! We should NOT be
        // making any requests here, and should READ what is already in the 
        // rootScope from the event handler service!!!
        // XXX FIXME TODO
        
        $rootScope.rooms = {};
        
        // Use initialSync data to init the recents list
        eventHandlerService.waitForInitialSyncCompletion().then(
            function(initialSyncData) {
            
                // XXX FIXME TODO:
                // Any assignments to the rootScope here should be done in
                // event handler service and not here, because we could have
                // many controllers manipulating and clobbering each other, and
                // are unecessarily repeating http requests.
                var rooms = initialSyncData.data.rooms;
                for (var i=0; i<rooms.length; i++) {
                    var room = rooms[i];
                    
                    // Add room_alias & room_display_name members
                    $rootScope.rooms[room.room_id] = angular.extend(room, matrixService.getRoomAliasAndDisplayName(room));

                    // Create a shortcut for the last message of this room
                    if (room.messages && room.messages.chunk && room.messages.chunk[0]) {
                        $rootScope.rooms[room.room_id].lastMsg = room.messages.chunk[0];
                    }
                    
                    
                    var numUsersInRoom = 0;
                    if (room.state) {
                        for (var j=0; j<room.state.length; j++) {
                            var stateEvent = room.state[j];
                            if (stateEvent.type == "m.room.member" && stateEvent.content.membership == "join") {
                                numUsersInRoom += 1;
                            }
                        }
                    }
                    $rootScope.rooms[room.room_id].numUsersInRoom = numUsersInRoom;
                }

                // From now, update recents from the stream
                listenToEventStream();
            },
            function(error) {
                $rootScope.feedback = "Failure: " + error.data;
            }
        );
    };
    
}]);

