/*
 Copyright 2014 matrix.org
 
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

angular.module('RecentsController', ['matrixService', 'eventHandlerService'])
.controller('RecentsController', ['$scope', 'matrixService', 'eventHandlerService', 
                               function($scope,  matrixService, eventHandlerService) {
    $scope.rooms = {};

    // $scope of the parent where the recents component is included can override this value
    // in order to highlight a specific room in the list
    $scope.recentsSelectedRoomID;

    var listenToEventStream = function() {
        // Refresh the list on matrix invitation and message event
        $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
            var config = matrixService.config();
            if (isLive && event.state_key === config.user_id && event.content.membership === "invite") {
                console.log("Invited to room " + event.room_id);
                // FIXME push membership to top level key to match /im/sync
                event.membership = event.content.membership;

                $scope.rooms[event.room_id] = event;
            }
        });
        $scope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $scope.rooms[event.room_id].lastMsg = event;              
            }
        });
        $scope.$on(eventHandlerService.CALL_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $scope.rooms[event.room_id].lastMsg = event;
            }
        });
        $scope.$on(eventHandlerService.ROOM_CREATE_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                $scope.rooms[event.room_id] = event;
            }
        });
    };

    
    var refresh = function() {
        // List all rooms joined or been invited to
        // TODO: This is a pity that event-stream-service.js makes the same call
        // We should be able to reuse event-stream-service.js fetched data
        matrixService.rooms(1, false).then(
            function(response) {
                // Reset data
                $scope.rooms = {};

                var rooms = response.data.rooms;
                for (var i=0; i<rooms.length; i++) {
                    var room = rooms[i];
                    
                    // Add room_alias & room_display_name members
                    $scope.rooms[room.room_id] = angular.extend(room, matrixService.getRoomAliasAndDisplayName(room));

                    // Create a shortcut for the last message of this room
                    if (room.messages && room.messages.chunk && room.messages.chunk[0]) {
                        $scope.rooms[room.room_id].lastMsg = room.messages.chunk[0];
                    }
                }

                var presence = response.data.presence;
                for (var i = 0; i < presence.length; ++i) {
                    eventHandlerService.handleEvent(presence[i], false);
                }

                // From now, update recents from the stream
                listenToEventStream();
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            }
        );
    };

    $scope.onInit = function() {
        eventHandlerService.waitForInitialSyncCompletion().then(function() {
            refresh();
        });
    };
    
}]);

