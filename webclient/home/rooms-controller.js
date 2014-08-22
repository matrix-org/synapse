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

angular.module('RoomsController', ['matrixService', 'mFileInput', 'mFileUpload', 'eventHandlerService'])
.controller('RoomsController', ['$scope', '$location', 'matrixService', 'mFileUpload', 'eventHandlerService', 'eventStreamService', 
                               function($scope, $location, matrixService, mFileUpload, eventHandlerService, eventStreamService) {

    $scope.config = matrixService.config();
    $scope.rooms = {};
    $scope.public_rooms = [];
    $scope.newRoomId = "";
    $scope.feedback = "";
    
    $scope.newRoom = {
        room_id: "",
        private: false
    };
    
    $scope.goToRoom = {
        room_id: "",
    };

    $scope.joinAlias = {
        room_alias: "",
    };
    
    $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
        var config = matrixService.config();
        if (event.target_user_id === config.user_id && event.content.membership === "invite") {
            console.log("Invited to room " + event.room_id);
            // FIXME push membership to top level key to match /im/sync
            event.membership = event.content.membership;
            // FIXME bodge a nicer name than the room ID for this invite.
            event.room_display_name = event.user_id + "'s room";
            $scope.rooms[event.room_id] = event;
        }
    });
    
    var assignRoomAliases = function(data) {
        for (var i=0; i<data.length; i++) {
            var alias = matrixService.getRoomIdToAliasMapping(data[i].room_id);
            if (alias) {
                // use the existing alias from storage
                data[i].room_alias = alias;
                data[i].room_display_name = alias;
            }
            else if (data[i].aliases && data[i].aliases[0]) {
                // save the mapping
                // TODO: select the smarter alias from the array
                matrixService.createRoomIdToAliasMapping(data[i].room_id, data[i].aliases[0]);
                data[i].room_display_name = data[i].aliases[0];
            }
            else if (data[i].membership == "invite" && "inviter" in data[i]) {
                data[i].room_display_name = data[i].inviter + "'s room"
            }
            else {
                // last resort use the room id
                data[i].room_display_name = data[i].room_id;
            }
        }
        return data;
    };

    $scope.refresh = function() {
        // List all rooms joined or been invited to
        matrixService.rooms().then(
            function(response) {
                var data = assignRoomAliases(response.data.rooms);
                $scope.feedback = "Success";
                for (var i=0; i<data.length; i++) {
                    $scope.rooms[data[i].room_id] = data[i];
                }

                var presence = response.data.presence;
                for (var i = 0; i < presence.length; ++i) {
                    eventHandlerService.handleEvent(presence[i], false);
                }
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            });
        
        matrixService.publicRooms().then(
            function(response) {
                $scope.public_rooms = assignRoomAliases(response.data.chunk);
            }
        );

        eventStreamService.resume();
    };
    
    $scope.createNewRoom = function(room_id, isPrivate) {
        
        var visibility = "public";
        if (isPrivate) {
            visibility = "private";
        }
        
        matrixService.create(room_id, visibility).then(
            function(response) { 
                // This room has been created. Refresh the rooms list
                console.log("Created room " + response.data.room_alias + " with id: "+
                response.data.room_id);
                matrixService.createRoomIdToAliasMapping(
                    response.data.room_id, response.data.room_alias);
                $scope.refresh();
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            });
    };
    
    // Go to a room
    $scope.goToRoom = function(room_id) {
        // Simply open the room page on this room id
        //$location.url("room/" + room_id);
        matrixService.join(room_id).then(
            function(response) {
                if (response.data.hasOwnProperty("room_id")) {
                    if (response.data.room_id != room_id) {
                        $location.url("room/" + response.data.room_id);
                        return;
                     }
                }

                $location.url("room/" + room_id);
            },
            function(error) {
                $scope.feedback = "Can't join room: " + error.data;
            }
        );
    };

    $scope.joinAlias = function(room_alias) {
        matrixService.joinAlias(room_alias).then(
            function(response) {
                // Go to this room
                $location.url("room/" + room_alias);
            },
            function(error) {
                $scope.feedback = "Can't join room: " + error.data;
            }
        );
    };
    
    $scope.refresh();
}]);
