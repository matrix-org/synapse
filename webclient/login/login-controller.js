angular.module('LoginController', ['matrixService'])
.controller('LoginController', ['$scope', '$location', 'matrixService', 'eventStreamService',
                                    function($scope, $location, matrixService, eventStreamService) {
    'use strict';
    
    
    // Assume that this is hosted on the home server, in which case the URL
    // contains the home server.
    var hs_url = $location.protocol() + "://" + $location.host();
    if ($location.port()) {
        hs_url += ":" + $location.port();
    }
    
    $scope.account = {
        homeserver: hs_url,
        desired_user_name: "",
        user_id: "",
        password: "",
        identityServer: "",
        pwd1: "",
        pwd2: ""
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
                 // Go to the user's rooms list page
                $location.path("rooms");
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

    $scope.login = function() {
        matrixService.setConfig({
            homeserver: $scope.account.homeserver,
            user_id: $scope.account.user_id
        });
        // try to login
        matrixService.login($scope.account.user_id, $scope.account.password).then(
            function(response) {
                if ("access_token" in response.data) {
                    $scope.feedback = "Login successful.";
                    matrixService.setConfig({
                        homeserver: $scope.account.homeserver,
                        user_id: response.data.user_id,
                        access_token: response.data.access_token
                    });
                    matrixService.saveConfig();
                    eventStreamService.resume();
                    $location.path("rooms");
                }
                else {
                    $scope.feedback = "Failed to login: " + JSON.stringify(response.data);
                }
            },
            function(error) {
                if (error.data) {
                    if (error.data.errcode === "M_FORBIDDEN") {
                        $scope.login_error_msg = "Incorrect username or password.";
                    }
                }
                else if (error.status === 0) {
                    $scope.login_error_msg = "Unable to talk to the server.";
                }
            }
        );
    };
}]);

