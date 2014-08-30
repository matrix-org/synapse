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
    var example_domain = $location.host();
    
    $scope.account = {
        homeserver: hs_url,
        example_domain: example_domain,
        desired_user_name: "",
        user_id: "",
        password: "",
        identityServer: "http://matrix.org:8090",
        pwd1: "",
        pwd2: "",
    };
    
    $scope.login_types = [ "email", "mxid" ];
    $scope.login_type_label = {
        "email": "Email address",
        "mxid": "Matrix ID (e.g. @bob:matrix.org or bob)",
    };
    $scope.login_type = 'mxid'; // TODO: remember the user's preferred login_type
    
    $scope.login = function() {
        matrixService.setConfig({
            homeserver: $scope.account.homeserver,
            identityServer: $scope.account.identityServer,
            user_id: $scope.account.user_id
        });
        // try to login
        matrixService.login($scope.account.user_id, $scope.account.password).then(
            function(response) {
                if ("access_token" in response.data) {
                    $scope.feedback = "Login successful.";
                    matrixService.setConfig({
                        homeserver: $scope.account.homeserver,
                        identityServer: $scope.account.identityServer,
                        user_id: response.data.user_id,
                        access_token: response.data.access_token
                    });
                    matrixService.saveConfig();
                    eventStreamService.resume();
                    $location.url("home");
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

