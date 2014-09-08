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
                $rootScope.rooms[event.room_id].lastMsg = event;
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
                }

                var presence = initialSyncData.data.presence;
                for (var i = 0; i < presence.length; ++i) {
                    eventHandlerService.handleEvent(presence[i], false);
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

