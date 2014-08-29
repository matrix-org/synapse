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

angular.module('SettingsController', ['matrixService', 'mFileUpload', 'mFileInput'])
.controller('SettingsController', ['$scope', 'matrixService', 'mFileUpload',
                              function($scope, matrixService, mFileUpload) {                 
    $scope.config = matrixService.config();

    $scope.profile = {
        displayName: $scope.config.displayName,
        avatarUrl: $scope.config.avatarUrl
    };
    
    $scope.$watch("profile.avatarFile", function(newValue, oldValue) {
        if ($scope.profile.avatarFile) {
            console.log("Uploading new avatar file...");
            mFileUpload.uploadFile($scope.profile.avatarFile).then(
                function(url) {
                    $scope.profile.avatarUrl = url;
                },
                function(error) {
                    $scope.feedback = "Can't upload image";
                } 
            );
        }
    });
    
    $scope.saveProfile = function() {
        if ($scope.profile.displayName !== $scope.config.displayName) {
            setDisplayName($scope.profile.displayName);
        }
        if ($scope.profile.avatarUrl !== $scope.config.avatarUrl) {
            setAvatar($scope.profile.avatarUrl);
        }
    };
    
    var setDisplayName = function(displayName) {
        matrixService.setDisplayName(displayName).then(
            function(response) {
                $scope.feedback = "Updated display name.";
                
                var config = matrixService.config();
                config.displayName = displayName;
                matrixService.setConfig(config);
                matrixService.saveConfig();
            },
            function(error) {
                $scope.feedback = "Can't update display name: " + error.data;
            }
        );
    };

    var setAvatar = function(avatarURL) {
        console.log("Updating avatar to " + avatarURL);
        matrixService.setProfilePictureUrl(avatarURL).then(
            function(response) {
                console.log("Updated avatar");
                $scope.feedback = "Updated avatar.";
                
                var config = matrixService.config();
                config.avatarUrl = avatarURL;
                matrixService.setConfig(config);
                matrixService.saveConfig();
            },
            function(error) {
                $scope.feedback = "Can't update avatar: " + error.data;
            }
        );
    };

    $scope.linkedEmails = {
        linkNewEmail: "", // the email entry box
        emailBeingAuthed: undefined, // to populate verification text
        authTokenId: undefined, // the token id from the IS
        emailCode: "", // the code entry box
        linkedEmailList: matrixService.config().emailList // linked email list
    };
    
    $scope.linkEmail = function(email) {
        matrixService.linkEmail(email).then(
            function(response) {
                if (response.data.success === true) {
                    $scope.linkedEmails.authTokenId = response.data.tokenId;
                    $scope.emailFeedback = "You have been sent an email.";
                    $scope.linkedEmails.emailBeingAuthed = email;
                }
                else {
                    $scope.emailFeedback = "Failed to send email.";
                }
            },
            function(error) {
                $scope.emailFeedback = "Can't send email: " + error.data;
            }
        );
    };

    $scope.submitEmailCode = function(code) {
        var tokenId = $scope.linkedEmails.authTokenId;
        if (tokenId === undefined) {
            $scope.emailFeedback = "You have not requested a code with this email.";
            return;
        }
        matrixService.authEmail(matrixService.config().user_id, tokenId, code).then(
            function(response) {
                if ("success" in response.data && response.data.success === false) {
                    $scope.emailFeedback = "Failed to authenticate email.";
                    return;
                }
                var config = matrixService.config();
                var emailList = {};
                if ("emailList" in config) {
                    emailList = config.emailList;
                }
                emailList[response.address] = response;
                // save the new email list
                config.emailList = emailList;
                matrixService.setConfig(config);
                matrixService.saveConfig();
                // invalidate the email being authed and update UI.
                $scope.linkedEmails.emailBeingAuthed = undefined;
                $scope.emailFeedback = "";
                $scope.linkedEmails.linkedEmailList = emailList;
                $scope.linkedEmails.linkNewEmail = "";
                $scope.linkedEmails.emailCode = "";
            },
            function(reason) {
                $scope.emailFeedback = "Failed to auth email: " + reason;
            }
        );
    };
    
    
    /*** Desktop notifications section ***/
    $scope.settings = {
        notifications: undefined
    };

    // If the browser supports it, check the desktop notification state
    if ("Notification" in window) {
        $scope.settings.notifications = window.Notification.permission;
    }

    $scope.requestNotifications = function() {
        console.log("requestNotifications");
        window.Notification.requestPermission(function (permission) {
            console.log("   -> User decision: " + permission);
            $scope.settings.notifications = permission;
        });
    };
}]);