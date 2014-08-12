angular.module('LoginController', ['matrixService'])
.controller('LoginController', ['$scope', '$location', 'matrixService',
                                    function($scope, $location, matrixService) {
    'use strict';
    
    $scope.account = {
        homeserver: "http://localhost:8080",
        desired_user_name: "",
        user_id: "",
        password: "",
        identityServer: "http://localhost:8090",
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
            function(data) {
                $scope.feedback = "Success";

                // Update the current config 
                var config = matrixService.config();
                angular.extend(config, {
                    access_token: data.access_token,
                    user_id: data.user_id
                });
                matrixService.setConfig(config);

                // And permanently save it
                matrixService.saveConfig();

                 // Go to the user's rooms list page
                $location.path("rooms");
            },
            function(reason) {
                $scope.feedback = "Failure: " + reason;
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
                if ("access_token" in response) {
                    $scope.feedback = "Login successful.";
                    matrixService.setConfig({
                        homeserver: $scope.account.homeserver,
                        user_id: $scope.account.user_id,
                        access_token: response.access_token
                    });
                    matrixService.saveConfig();
                    $location.path("rooms");
                }
                else {
                    $scope.feedback = "Failed to login: " + JSON.stringify(response);
                }
            }
        );
    };
}]);

