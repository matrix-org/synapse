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
 
angular.module('RegisterController', ['matrixService'])
.controller('RegisterController', ['$scope', '$location', 'matrixService', 'eventStreamService',
                                    function($scope, $location, matrixService, eventStreamService) {
    'use strict';
    
    // FIXME: factor out duplication with login-controller.js
    
    // Assume that this is hosted on the home server, in which case the URL
    // contains the home server.
    var hs_url = $location.protocol() + "://" + $location.host();
    if ($location.port() &&
        !($location.protocol() === "http" && $location.port() === 80) &&
        !($location.protocol() === "https" && $location.port() === 443))
    {
        hs_url += ":" + $location.port();
    }
    
    $scope.account = {
        homeserver: hs_url,
        desired_user_name: "",
        user_id: "",
        password: "",
        identityServer: "http://matrix.org:8090",
        pwd1: "",
        pwd2: "",
        displayName : ""
    };
    
    $scope.register = function() {

        // Set the urls
        matrixService.setConfig({
            homeserver: $scope.account.homeserver,
            identityServer: $scope.account.identityServer
        });
        
        if ($scope.account.pwd1 !== $scope.account.pwd2) {
            $scope.feedback = "Passwords don't match.";
            return;
        }
        else if ($scope.account.pwd1.length < 6) {
            $scope.feedback = "Password must be at least 6 characters.";
            return;
        }

        matrixService.register($scope.account.desired_user_name, $scope.account.pwd1).then(
            function(response) {
                $scope.feedback = "Success";
                // Update the current config 
                var config = matrixService.config();
                angular.extend(config, {
                    access_token: response.data.access_token,
                    user_id: response.data.user_id
                });
                matrixService.setConfig(config);

                // And permanently save it
                matrixService.saveConfig();
                eventStreamService.resume();
                
                if ($scope.account.displayName) {
                    // FIXME: handle errors setting displayName
                    matrixService.setDisplayName($scope.account.displayName);
                }
                
                 // Go to the user's rooms list page
                $location.url("home");
            },
            function(error) {
                if (error.data) {
                    if (error.data.errcode === "M_USER_IN_USE") {
                        $scope.feedback = "Username already taken.";
                    }
                }
                else if (error.status === 0) {
                    $scope.feedback = "Unable to talk to the server.";
                }
            });
    };

}]);

