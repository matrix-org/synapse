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
.controller('RecentsController', ['$scope', 'matrixService', 'eventHandlerService', 'eventStreamService', 
                               function($scope,  matrixService, eventHandlerService, eventStreamService) {
    $scope.rooms = {};

    // $scope of the parent where the recents component is included can override this value
    // in order to highlight a specific room in the list
    $scope.recentsSelectedRoomID;

    // Refresh the list on matrix invitation and message event
    $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
        refresh();
    });
    $scope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
        refresh();
    });
    
    var refresh = function() {
        // List all rooms joined or been invited to
        // TODO: This is a pity that event-stream-service.js makes the same call
        // We should be able to reuse event-stream-service.js fetched data
        matrixService.rooms(1, false).then(
            function(response) {
                // Reset data
                $scope.rooms = {};

                var data = matrixService.assignRoomAliases(response.data.rooms);
                for (var i=0; i<data.length; i++) {
                    $scope.rooms[data[i].room_id] = data[i];

                    // Create a shortcut for the last message of this room
                    if (data[i].messages && data[i].messages.chunk && data[i].messages.chunk[0]) {
                        $scope.rooms[data[i].room_id].lastMsg = data[i].messages.chunk[0];
                    }
                }

                var presence = response.data.presence;
                for (var i = 0; i < presence.length; ++i) {
                    eventHandlerService.handleEvent(presence[i], false);
                }
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            }
        );
    };

    $scope.onInit = function() {
        refresh();
    };
    
}]);

