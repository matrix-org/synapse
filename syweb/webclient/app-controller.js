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

/*
 * Main controller
 */

'use strict';

angular.module('MatrixWebClientController', ['matrixService', 'mPresence', 'eventStreamService'])
.controller('MatrixWebClientController', ['$scope', '$location', '$rootScope', '$timeout', '$animate', 'matrixService', 'mPresence', 'eventStreamService', 'eventHandlerService', 'matrixPhoneService', 'modelService',
                               function($scope, $location, $rootScope, $timeout, $animate, matrixService, mPresence, eventStreamService, eventHandlerService, matrixPhoneService, modelService) {
         
    // Check current URL to avoid to display the logout button on the login page
    $scope.location = $location.path();

    // disable nganimate for the local and remote video elements because ngAnimate appears
    // to be buggy and leaves animation classes on the video elements causing them to show
    // when they should not (their animations are pure CSS3)
    $animate.enabled(false, angular.element('#localVideo'));
    $animate.enabled(false, angular.element('#remoteVideo'));
    
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
    $rootScope.goToPage = function(url) {
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
    
    $scope.leave = function(room_id) {
        matrixService.leave(room_id).then(
            function(response) {
                console.log("Left room " + room_id);
            },
            function(error) {
                console.log("Failed to leave room " + room_id + ": " + error.data.error);
            });
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

        // Reset cached data
        eventHandlerService.reset();

        // And go to the login page
        $location.url("login");
    };

    // Listen to the event indicating that the access token is no longer valid.
    // In this case, the user needs to log in again.
    $scope.$on("M_UNKNOWN_TOKEN", function() {
        console.log("Invalid access token -> log user out");
        $scope.logout();
    });
    
    $rootScope.updateHeader = function() {
        $scope.user_id = matrixService.config().user_id;
    };

    $rootScope.$watch('currentCall', function(newVal, oldVal) {
        if (!$rootScope.currentCall) {
            // This causes the still frame to be flushed out of the video elements,
            // avoiding a flash of the last frame of the previous call when starting the next
            if (angular.element('#localVideo')[0].load) angular.element('#localVideo')[0].load();
            if (angular.element('#remoteVideo')[0].load) angular.element('#remoteVideo')[0].load();
            return;
        }

        var roomMembers = angular.copy(modelService.getRoom($rootScope.currentCall.room_id).current_room_state.members);
        delete roomMembers[matrixService.config().user_id];

        $rootScope.currentCall.user_id = Object.keys(roomMembers)[0];

        // set it to the user ID until we fetch the display name
        $rootScope.currentCall.userProfile = { displayname: $rootScope.currentCall.user_id };

        matrixService.getProfile($rootScope.currentCall.user_id).then(
            function(response) {
                if (response.data.displayname) $rootScope.currentCall.userProfile.displayname = response.data.displayname;
                if (response.data.avatar_url) $rootScope.currentCall.userProfile.avatar_url = response.data.avatar_url;
            },
            function(error) {
                $scope.feedback = "Can't load user profile";
            }
        );
    });
    $rootScope.$watch('currentCall.state', function(newVal, oldVal) {
        if (newVal == 'ringing') {
            angular.element('#ringbackAudio')[0].pause();
            angular.element('#ringAudio')[0].load();
            angular.element('#ringAudio')[0].play();
        } else if (newVal == 'invite_sent') {
            angular.element('#ringAudio')[0].pause();
            angular.element('#ringbackAudio')[0].load();
            angular.element('#ringbackAudio')[0].play();
        } else if (newVal == 'ended' && oldVal == 'connected') {
            angular.element('#ringAudio')[0].pause();
            angular.element('#ringbackAudio')[0].pause();
            angular.element('#callendAudio')[0].play();
            $scope.videoMode = undefined;
        } else if (newVal == 'ended' && oldVal == 'invite_sent' && $rootScope.currentCall.hangupParty == 'remote') {
            angular.element('#ringAudio')[0].pause();
            angular.element('#ringbackAudio')[0].pause();
            angular.element('#busyAudio')[0].play();
        } else if (newVal == 'ended' && oldVal == 'invite_sent' && $rootScope.currentCall.hangupParty == 'local' && $rootScope.currentCall.hangupReason == 'invite_timeout') {
            angular.element('#ringAudio')[0].pause();
            angular.element('#ringbackAudio')[0].pause();
            angular.element('#busyAudio')[0].play();
        } else if (oldVal == 'invite_sent') {
            angular.element('#ringbackAudio')[0].pause();
        } else if (oldVal == 'ringing') {
            angular.element('#ringAudio')[0].pause();
        } else if (newVal == 'connected') {
            $timeout(function() {
                if ($scope.currentCall.type == 'video') $scope.videoMode = 'large';
            }, 500);
        }

        if ($rootScope.currentCall && $rootScope.currentCall.type == 'video' && $rootScope.currentCall.state != 'connected') {
            $scope.videoMode = 'mini';
        }
    });
    $rootScope.$watch('currentCall.type', function(newVal, oldVal) {
        // need to listen for this too as the type of the call won't be know when it's created
        if ($rootScope.currentCall && $rootScope.currentCall.type == 'video' && $rootScope.currentCall.state != 'connected') {
            $scope.videoMode = 'mini';
        }
    });

    $rootScope.$on(matrixPhoneService.INCOMING_CALL_EVENT, function(ngEvent, call) {
        console.log("incoming call");
        if ($rootScope.currentCall && $rootScope.currentCall.state != 'ended') {
            console.log("rejecting call because we're already in a call");
            call.hangup();
            return;
        }
        call.onError = $scope.onCallError;
        call.onHangup = $scope.onCallHangup;
        call.localVideoSelector  = '#localVideo';
        call.remoteVideoSelector  = '#remoteVideo';
        $rootScope.currentCall = call;
    });

    $rootScope.$on(matrixPhoneService.REPLACED_CALL_EVENT, function(ngEvent, oldCall, newCall) {
        console.log("call ID "+oldCall.call_id+" has been replaced by call ID "+newCall.call_id+"!");
        newCall.onError = $scope.onCallError;
        newCall.onHangup = $scope.onCallHangup;
        $rootScope.currentCall = newCall;
    });

    $scope.answerCall = function() {
        $rootScope.currentCall.answer();
    };

    $scope.hangupCall = function() {
        $rootScope.currentCall.hangup();
    };
    
    $rootScope.onCallError = function(errStr) {
        $scope.feedback = errStr;
    };

    $rootScope.onCallHangup = function(call) {
        if (call == $rootScope.currentCall) {
            $timeout(function(){
                if (call == $rootScope.currentCall) $rootScope.currentCall = undefined;
            }, 4070);
        }
    };
}]);
