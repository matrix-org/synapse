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

angular.module('HomeController', ['matrixService', 'eventHandlerService', 'RecentsController'])
.controller('HomeController', ['$scope', '$location', 'matrixService', 'eventHandlerService', 'modelService',
                               function($scope, $location, matrixService, eventHandlerService, modelService) {

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
    
    $scope.newChat = {
        user: ""
    };

    var refresh = function() {
        
        matrixService.publicRooms().then(
            function(response) {
                $scope.public_rooms = response.data.chunk;
                for (var i = 0; i < $scope.public_rooms.length; i++) {
                    var room = $scope.public_rooms[i];
                    
                    if (room.aliases && room.aliases.length > 0) {
                        room.room_display_name = room.aliases[0];
                        room.room_alias = room.aliases[0];
                    }
                    else if (room.name) {
                        room.room_display_name = room.name;
                    }
                    else {
                        room.room_display_name = room.room_id;
                    }
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
                modelService.createRoomIdToAliasMapping(
                    response.data.room_id, response.data.room_alias);
            },
            function(error) {
                $scope.feedback = "Failure: " + JSON.stringify(error.data);
            });
    };
    
    // Go to a room
    $scope.goToRoom = function(room_id) {
        matrixService.join(room_id).then(
            function(response) {
                var final_room_id = room_id;
                if (response.data.hasOwnProperty("room_id")) {
                    final_room_id = response.data.room_id;
                }

                // TODO: factor out the common housekeeping whenever we try to join a room or alias
                matrixService.roomState(final_room_id).then(
                    function(response) {
                        eventHandlerService.handleEvents(response.data, false, true);
                    },
                    function(error) {
                        $scope.feedback = "Failed to get room state for: " + final_room_id;
                    }
                );                                        

                $location.url("room/" + final_room_id);
            },
            function(error) {
                $scope.feedback = "Can't join room: " + JSON.stringify(error.data);
            }
        );
    };

    $scope.joinAlias = function(room_alias) {
        matrixService.joinAlias(room_alias).then(
            function(response) {
                // TODO: factor out the common housekeeping whenever we try to join a room or alias
                matrixService.roomState(response.room_id).then(
                    function(response) {
                        eventHandlerService.handleEvents(response.data, false, true);
                    },
                    function(error) {
                        $scope.feedback = "Failed to get room state for: " + response.room_id;
                    }
                );                                        
                // Go to this room
                $location.url("room/" + room_alias);
            },
            function(error) {
                $scope.feedback = "Can't join room: " + JSON.stringify(error.data);
            }
        );
    };
    
    // FIXME: factor this out between user-controller and home-controller etc.
    $scope.messageUser = function() {    
        
        // FIXME: create a new room every time, for now
        
        matrixService.create(null, 'private').then(
            function(response) { 
                // This room has been created. Refresh the rooms list
                var room_id = response.data.room_id;
                console.log("Created room with id: "+ room_id);
                
                matrixService.invite(room_id, $scope.newChat.user).then(
                    function() {
                        $scope.feedback = "Invite sent successfully";
                        $scope.$parent.goToPage("/room/" + room_id);
                    },
                    function(reason) {
                        $scope.feedback = "Failure: " + JSON.stringify(reason);
                    });
            },
            function(error) {
                $scope.feedback = "Failure: " + JSON.stringify(error.data);
            });                
    };
    
 
    $scope.onInit = function() {
        // Load profile data
        // Display name
        matrixService.getDisplayName($scope.config.user_id).then(
            function(response) {
                $scope.profile.displayName = response.data.displayname;
                var config = matrixService.config();
                config.display_name = response.data.displayname;
                matrixService.setConfig(config);
                matrixService.saveConfig();
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

        // Listen to room creation event in order to update the public rooms list
        $scope.$on(eventHandlerService.ROOM_CREATE_EVENT, function(ngEvent, event, isLive) {
            if (isLive) {
                // As we do not know if this room is public, do a full list refresh
                refresh();
            }
        });

        refresh();
    };

    // Clean data when user logs out
    $scope.$on(eventHandlerService.RESET_EVENT, function() {
        $scope.public_rooms = [];
    });
}]);
