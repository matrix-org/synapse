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

angular.module('HomeController', ['matrixService', 'eventHandlerService', 'RecentsController'])
.controller('HomeController', ['$scope', '$location', 'matrixService', 
                               function($scope, $location, matrixService) {

    $scope.config = matrixService.config();
    $scope.public_rooms = [];
    $scope.newRoomId = "";
    $scope.feedback = "";
    
    $scope.newRoom = {
        room_id: "",
        private: false
    };
    
    $scope.goToRoom = {
        room_id: ""
    };

    $scope.joinAlias = {
        room_alias: ""
    };
    
    $scope.profile = {
        displayName: "",
        avatarUrl: ""
    };

    var refresh = function() {
        
        matrixService.publicRooms().then(
            function(response) {
                $scope.public_rooms = response.data.chunk;
                for (var i = 0; i < $scope.public_rooms.length; i++) {
                    var room = $scope.public_rooms[i];

                    // Add room_alias & room_display_name members
                    angular.extend(room, matrixService.getRoomAliasAndDisplayName(room));
                }
            }
        );
    };
    
    $scope.createNewRoom = function(room_alias, isPrivate) {
        
        var visibility = "public";
        if (isPrivate) {
            visibility = "private";
        }
        
        matrixService.create(room_alias, visibility).then(
            function(response) { 
                // This room has been created. Refresh the rooms list
                console.log("Created room " + response.data.room_alias + " with id: "+
                response.data.room_id);
                matrixService.createRoomIdToAliasMapping(
                    response.data.room_id, response.data.room_alias);
                refresh();
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
 
    $scope.onInit = function() {
        // Load profile data
        // Display name
        matrixService.getDisplayName($scope.config.user_id).then(
            function(response) {
                $scope.profile.displayName = response.data.displayname;
            },
            function(error) {
                $scope.feedback = "Can't load display name";
            } 
        );
        // Avatar
        matrixService.getProfilePictureUrl($scope.config.user_id).then(
            function(response) {
                $scope.profile.avatarUrl = response.data.avatar_url;
            },
            function(error) {
                $scope.feedback = "Can't load avatar URL";
            } 
        );

        refresh();
    };
}]);
