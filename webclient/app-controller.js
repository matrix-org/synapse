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

/*
 * Main controller
 */

'use strict';

angular.module('MatrixWebClientController', ['matrixService', 'mPresence', 'eventStreamService'])
.controller('MatrixWebClientController', ['$scope', '$location', '$rootScope', 'matrixService', 'mPresence', 'eventStreamService', 'matrixPhoneService',
                               function($scope, $location, $rootScope, matrixService, mPresence, eventStreamService, matrixPhoneService) {
         
    // Check current URL to avoid to display the logout button on the login page
    $scope.location = $location.path();
    
    // Update the location state when the ng location changed
    $rootScope.$on('$routeChangeSuccess', function (event, current, previous) {
        $scope.location = $location.path();
    });

    if (matrixService.isUserLoggedIn()) {
        eventStreamService.resume();
        mPresence.start();
    }

    $scope.user_id;
    var config = matrixService.config();
    if (config) {
        $scope.user_id = matrixService.config().user_id;
    }
    
    /**
     * Open a given page.
     * @param {String} url url of the page
     */
    $scope.goToPage = function(url) {
        $location.url(url);
    };
    
    // Open the given user profile page
    $scope.goToUserPage = function(user_id) {
        if (user_id === $scope.user_id) {
            $location.url("/settings");
        }
        else {
            $location.url("/user/" + user_id);
        }
    };
    
    // Logs the user out 
    $scope.logout = function() {
        
        // kill the event stream
        eventStreamService.stop();

        // Do not update presence anymore
        mPresence.stop();

        // Clean permanent data
        matrixService.setConfig({});
        matrixService.saveConfig();
        
        // And go to the login page
        $location.url("login");
    };

    // Listen to the event indicating that the access token is no longer valid.
    // In this case, the user needs to log in again.
    $scope.$on("M_UNKNOWN_TOKEN", function() {
        console.log("Invalid access token -> log user out");
        $scope.logout();
    });
    
    $scope.updateHeader = function() {
        $scope.user_id = matrixService.config().user_id;
    };

    $rootScope.$on(matrixPhoneService.INCOMING_CALL_EVENT, function(ngEvent, call) {
        console.trace("incoming call");
        call.onError = $scope.onCallError;
        call.onHangup = $scope.onCallHangup;
        $rootScope.currentCall = call;
    });

    $scope.answerCall = function() {
        $scope.currentCall.answer();
    };

    $scope.hangupCall = function() {
        $scope.currentCall.hangup();
        $scope.currentCall = undefined;
    };
    
    $rootScope.onCallError = function(errStr) {
        $scope.feedback = errStr;
    }

    $rootScope.onCallHangup = function() {
    }
}]);
