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

angular.module('UserController', ['matrixService'])
.controller('UserController', ['$scope', '$routeParams', 'matrixService',
                              function($scope, $routeParams, matrixService) {                 
    $scope.user = {
        id: $routeParams.user_matrix_id,
        displayname: "",
        avatar_url: undefined
    };
    
    $scope.user_id = matrixService.config().user_id;
    
    matrixService.getDisplayName($scope.user.id).then(
        function(response) {
            $scope.user.displayname = response.data.displayname;
        }
    ); 
    
    matrixService.getProfilePictureUrl($scope.user.id).then(
        function(response) {
            $scope.user.avatar_url = response.data.avatar_url;
        }
    );

    // FIXME: factor this out between user-controller and home-controller etc.
    $scope.messageUser = function() {    
        
        // FIXME: create a new room every time, for now
        
        matrixService.create(null, 'private').then(
            function(response) { 
                // This room has been created. Refresh the rooms list
                var room_id = response.data.room_id;
                console.log("Created room with id: "+ room_id);
                
                matrixService.invite(room_id, $scope.user.id).then(
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
    
}]);