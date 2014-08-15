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

angular.module('RoomController', [])
.controller('RoomController', ['$scope', '$http', '$timeout', '$routeParams', '$location', 'matrixService', 'eventStreamService', 'eventHandlerService',
                               function($scope, $http, $timeout, $routeParams, $location, matrixService, eventStreamService, eventHandlerService) {
   'use strict';
    var MESSAGES_PER_PAGINATION = 10;
    $scope.room_id = $routeParams.room_id;
    $scope.room_alias = matrixService.getRoomIdToAliasMapping($scope.room_id);
    $scope.state = {
        user_id: matrixService.config().user_id,
        events_from: "END", // when to start the event stream from.
        earliest_token: "END", // stores how far back we've paginated.
        can_paginate: true, // this is toggled off when we run out of items
        stream_failure: undefined // the response when the stream fails
    };
    $scope.messages = [];
    $scope.members = {};
    $scope.stopPoll = false;

    $scope.imageURLToSend = "";
    $scope.userIDToInvite = "";
    
    var scrollToBottom = function() {
        $timeout(function() {
            var objDiv = document.getElementsByClassName("messageTableWrapper")[0];
            objDiv.scrollTop = objDiv.scrollHeight;
        },0);
    };
    
    $scope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
        if (isLive) {
            $scope.messages.push(event);
            scrollToBottom();
        }
        else {
            $scope.messages.unshift(event);
        }
    });
    
    $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
        updateMemberList(event);
    });
    
    $scope.$on(eventHandlerService.PRESENCE_EVENT, function(ngEvent, event, isLive) {
        updatePresence(event);
    });
    
    var paginate = function(numItems) {
        matrixService.paginateBackMessages($scope.room_id, $scope.state.earliest_token, numItems).then(
            function(response) {
                eventHandlerService.handleEvents(response.data.chunk, false);
                $scope.state.earliest_token = response.data.end;
                if (response.data.chunk.length < MESSAGES_PER_PAGINATION) {
                    // no more messages to paginate :(
                    $scope.state.can_paginate = false;
                }
            },
            function(error) {
                console.log("Failed to paginateBackMessages: " + JSON.stringify(error));
            }
        )
    };

    var shortPoll = function() {
        eventStreamService.resume().then(
            function(response) {
                $scope.state.stream_failure = undefined;
                console.log("Got response from "+$scope.state.events_from+" to "+response.data.end);
                $scope.state.events_from = response.data.end;
                $scope.feedback = "";
                
                eventHandlerService.handleEvents(response.data.chunk, true);
                
                if ($scope.stopPoll) {
                    console.log("Stopping polling.");
                }
                else {
                    $timeout(shortPoll, 0);
                }
            }, 
            function(error) {
                $scope.state.stream_failure = error;

                if (error.status == 403) {
                    $scope.stopPoll = true;
                }
                
                if ($scope.stopPoll) {
                    console.log("Stopping polling.");
                }
                else {
                    $timeout(shortPoll, 5000);
                }
            }
        );
    };

    var updateMemberList = function(chunk) {
        var isNewMember = !(chunk.target_user_id in $scope.members);
        if (isNewMember) {
            $scope.members[chunk.target_user_id] = chunk;
            // get their display name and profile picture and set it to their
            // member entry in $scope.members. We HAVE to use $timeout with 0 delay 
            // to make this function run AFTER the current digest cycle, else the 
            // response may update a STALE VERSION of the member list (manifesting
            // as no member names appearing, or appearing sporadically).
            $scope.$evalAsync(function() {
                matrixService.getDisplayName(chunk.target_user_id).then(
                    function(response) {
                        var member = $scope.members[chunk.target_user_id];
                        if (member !== undefined) {
                            console.log("Updated displayname "+chunk.target_user_id+" to " + response.data.displayname);
                            member.displayname = response.data.displayname;
                        }
                    }
                ); 
                matrixService.getProfilePictureUrl(chunk.target_user_id).then(
                    function(response) {
                         var member = $scope.members[chunk.target_user_id];
                         if (member !== undefined) {
                            console.log("Updated image for "+chunk.target_user_id+" to " + response.data.avatar_url);
                            member.avatar_url = response.data.avatar_url;
                         }
                    }
                );
            });
        }
        else {
            // selectively update membership else it will nuke the picture and displayname too :/
            var member = $scope.members[chunk.target_user_id];
            member.content.membership = chunk.content.membership;
        }
    }

    var updatePresence = function(chunk) {
        if (!(chunk.content.user_id in $scope.members)) {
            console.log("updatePresence: Unknown member for chunk " + JSON.stringify(chunk));
            return;
        }
        var member = $scope.members[chunk.content.user_id];

        if ("state" in chunk.content) {
            if (chunk.content.state === "online") {
                member.presenceState = "online";
            }
            else if (chunk.content.state === "offline") {
                member.presenceState = "offline";
            }
            else if (chunk.content.state === "unavailable") {
                member.presenceState = "unavailable";
            }
        }

        // this may also contain a new display name or avatar url, so check.
        if ("displayname" in chunk.content) {
            member.displayname = chunk.content.displayname;
        }

        if ("avatar_url" in chunk.content) {
            member.avatar_url = chunk.content.avatar_url;
        }
    }

    $scope.send = function() {
        if ($scope.textInput == "") {
            return;
        }
                    
        // Send the text message
        var promise;
        // FIXME: handle other commands too
        if ($scope.textInput.indexOf("/me") == 0) {
            promise = matrixService.sendEmoteMessage($scope.room_id, $scope.textInput.substr(4));
        }
        else {
            promise = matrixService.sendTextMessage($scope.room_id, $scope.textInput);
        }
        
        promise.then(
            function() {
                console.log("Sent message");
                $scope.textInput = "";
            },
            function(error) {
                $scope.feedback = "Failed to send: " + error.data.error;
            });               
    };

    $scope.onInit = function() {
        // $timeout(function() { document.getElementById('textInput').focus() }, 0);
        console.log("onInit");

        // Join the room
        matrixService.join($scope.room_id).then(
            function() {
                console.log("Joined room "+$scope.room_id);
                // Now start reading from the stream
                $timeout(shortPoll, 0);

                // Get the current member list
                matrixService.getMemberList($scope.room_id).then(
                    function(response) {
                        for (var i = 0; i < response.data.chunk.length; i++) {
                            var chunk = response.data.chunk[i];
                            updateMemberList(chunk);
                        }
                    },
                    function(error) {
                        $scope.feedback = "Failed get member list: " + error.data.error;
                    }
                );
                
                paginate(MESSAGES_PER_PAGINATION);
            },
            function(reason) {
                $scope.feedback = "Can't join room: " + reason;
            });
    }; 
    
    $scope.inviteUser = function(user_id) {
        
        matrixService.invite($scope.room_id, user_id).then(
            function() {
                console.log("Invited.");
                $scope.feedback = "Request for invitation succeeds";
            },
            function(reason) {
                $scope.feedback = "Failure: " + reason;
            });
    };

    $scope.leaveRoom = function() {
        
        matrixService.leave($scope.room_id).then(
            function(response) {
                console.log("Left room ");
                $location.path("rooms");
            },
            function(error) {
                $scope.feedback = "Failed to leave room: " + error.data.error;
            });
    };

    $scope.sendImage = function(url) {
        matrixService.sendImageMessage($scope.room_id, url).then(
            function() {
                console.log("Image sent");
            },
            function(error) {
                $scope.feedback = "Failed to send image: " + error.data.error;
            });
    };
    
    $scope.loadMoreHistory = function() {
        paginate(MESSAGES_PER_PAGINATION);
    };

    $scope.$on('$destroy', function(e) {
        console.log("onDestroyed: Stopping poll.");
        $scope.stopPoll = true;
    });
}]);
