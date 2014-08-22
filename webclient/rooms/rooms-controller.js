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

angular.module('RoomsController', ['matrixService', 'mFileInput', 'mFileUpload', 'eventHandlerService'])
.controller('RoomsController', ['$scope', '$location', 'matrixService', 'mFileUpload', 'eventHandlerService',
                               function($scope, $location, matrixService, mFileUpload, eventHandlerService) {
                                   
    $scope.rooms = {};
    $scope.public_rooms = [];
    $scope.newRoomId = "";
    $scope.feedback = "";
    
    $scope.newRoom = {
        room_id: "",
        private: false
    };
    
    $scope.goToRoom = {
        room_id: "",
    };

    $scope.joinAlias = {
        room_alias: "",
    };

    $scope.newProfileInfo = {
        name: matrixService.config().displayName,
        avatar: matrixService.config().avatarUrl,
        avatarFile: undefined
    };

    $scope.linkedEmails = {
        linkNewEmail: "", // the email entry box
        emailBeingAuthed: undefined, // to populate verification text
        authTokenId: undefined, // the token id from the IS
        clientSecret: undefined, // our client secret
        sendAttempt: 1,
        emailCode: "", // the code entry box
        linkedEmailList: matrixService.config().emailList // linked email list
    };
    
    $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
        var config = matrixService.config();
        if (event.target_user_id === config.user_id && event.content.membership === "invite") {
            console.log("Invited to room " + event.room_id);
            // FIXME push membership to top level key to match /im/sync
            event.membership = event.content.membership;
            // FIXME bodge a nicer name than the room ID for this invite.
            event.room_alias = event.user_id + "'s room";
            $scope.rooms[event.room_id] = event;
        }
    });
    
    var assignRoomAliases = function(data) {
        for (var i=0; i<data.length; i++) {
            var alias = matrixService.getRoomIdToAliasMapping(data[i].room_id);
            if (alias) {
                // use the existing alias from storage
                data[i].room_alias = alias;
            }
            else if (data[i].aliases && data[i].aliases[0]) {
                // save the mapping
                // TODO: select the smarter alias from the array
                matrixService.createRoomIdToAliasMapping(data[i].room_id, data[i].aliases[0]);
            }
            else {
                // last resort use the room id
                data[i].room_alias = data[i].room_id;
            }
        }
        return data;
    };

    $scope.refresh = function() {
        // List all rooms joined or been invited to
        matrixService.rooms().then(
            function(response) {
                var data = assignRoomAliases(response.data);
                $scope.feedback = "Success";
                for (var i=0; i<data.length; i++) {
                    $scope.rooms[data[i].room_id] = data[i];
                }
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            });
        
        matrixService.publicRooms().then(
            function(response) {
                $scope.public_rooms = assignRoomAliases(response.data.chunk);
            }
        );
    };
    
    $scope.createNewRoom = function(room_id, isPrivate) {
        
        var visibility = "public";
        if (isPrivate) {
            visibility = "private";
        }
        
        matrixService.create(room_id, visibility).then(
            function(response) { 
                // This room has been created. Refresh the rooms list
                console.log("Created room " + response.data.room_alias + " with id: "+
                response.data.room_id);
                matrixService.createRoomIdToAliasMapping(
                    response.data.room_id, response.data.room_alias);
                $scope.refresh();
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            });
    };
    
    // Go to a room
    $scope.goToRoom = function(room_id) {
        // Simply open the room page on this room id
        //$location.path("room/" + room_id);
        matrixService.join(room_id).then(
            function(response) {
                if (response.data.hasOwnProperty("room_id")) {
                    if (response.data.room_id != room_id) {
                        $location.path("room/" + response.data.room_id);
                        return;
                     }
                }

                $location.path("room/" + room_id);
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
                $location.path("room/" + room_alias);
            },
            function(error) {
                $scope.feedback = "Can't join room: " + error.data;
            }
        );
    };

    $scope.setDisplayName = function(newName) {
        matrixService.setDisplayName(newName).then(
            function(response) {
                $scope.feedback = "Updated display name.";
                var config = matrixService.config();
                config.displayName = newName;
                matrixService.setConfig(config);
                matrixService.saveConfig();
            },
            function(error) {
                $scope.feedback = "Can't update display name: " + error.data;
            }
        );
    };


    $scope.$watch("newProfileInfo.avatarFile", function(newValue, oldValue) {
        if ($scope.newProfileInfo.avatarFile) {
            console.log("Uploading new avatar file...");
            mFileUpload.uploadFile($scope.newProfileInfo.avatarFile).then(
                function(url) {
                    $scope.newProfileInfo.avatar = url;
                    $scope.setAvatar($scope.newProfileInfo.avatar);
                },
                function(error) {
                    $scope.feedback = "Can't upload image";
                } 
            );
        }
    });

    $scope.setAvatar = function(newUrl) {
        console.log("Updating avatar to "+newUrl);
        matrixService.setProfilePictureUrl(newUrl).then(
            function(response) {
                console.log("Updated avatar");
                $scope.feedback = "Updated avatar.";
                var config = matrixService.config();
                config.avatarUrl = newUrl;
                matrixService.setConfig(config);
                matrixService.saveConfig();
            },
            function(error) {
                $scope.feedback = "Can't update avatar: " + error.data;
            }
        );
    };

    var generateClientSecret = function() {
        var ret = "";
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (var i = 0; i < 32; i++) {
            ret += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return ret;
    };


    $scope.linkEmail = function(email) {
        if (email != $scope.linkedEmails.emailBeingAuthed) {
            $scope.linkedEmails.clientSecret = generateClientSecret();
            $scope.linkedEmails.sendAttempt = 1;
        }
        matrixService.linkEmail(email, $scope.linkedEmails.clientSecret, $scope.linkedEmails.sendAttempt).then(
            function(response) {
                if (response.data.success === true) {
                    $scope.linkedEmails.authTokenId = response.data.sid;
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
        matrixService.authEmail(matrixService.config().user_id, tokenId, code, $scope.linkedEmails.clientSecret).then(
            function(response) {
                if ("success" in response.data && response.data.success === false) {
                    $scope.emailFeedback = "Failed to authenticate email.";
                    return;
                }
                matrixService.bindEmail(matrixService.config().user_id, tokenId, $scope.linkedEmails.clientSecret).then(
                    function(response) {
                         var config = matrixService.config();
                         var emailList = {};
                         if ("emailList" in config) {
                             emailList = config.emailList;
                         }
                         emailList[$scope.linkedEmails.emailBeingAuthed] = response;
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
                    }, function(reason) {
                        $scope.emailFeedback = "Failed to link email: " + reason;
                    }
                );
            },
            function(reason) {
                $scope.emailFeedback = "Failed to auth email: " + reason;
            }
        );
    };
    
    $scope.refresh();
}]);
