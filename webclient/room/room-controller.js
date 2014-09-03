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

angular.module('RoomController', ['ngSanitize', 'mFileInput'])
.controller('RoomController', ['$scope', '$timeout', '$routeParams', '$location', '$rootScope', 'matrixService', 'eventHandlerService', 'mFileUpload', 'mPresence', 'matrixPhoneService', 'MatrixCall',
                               function($scope, $timeout, $routeParams, $location, $rootScope, matrixService, eventHandlerService, mFileUpload, mPresence, matrixPhoneService, MatrixCall) {
   'use strict';
    var MESSAGES_PER_PAGINATION = 30;
    var THUMBNAIL_SIZE = 320;

    // Room ids. Computed and resolved in onInit
    $scope.room_id = undefined;
    $scope.room_alias = undefined;

    $scope.state = {
        user_id: matrixService.config().user_id,
        events_from: "END", // when to start the event stream from.
        earliest_token: "END", // stores how far back we've paginated.
        first_pagination: true, // this is toggled off when the first pagination is done
        can_paginate: true, // this is toggled off when we run out of items
        paginating: false, // used to avoid concurrent pagination requests pulling in dup contents
        stream_failure: undefined, // the response when the stream fails
        // FIXME: sending has been disabled, as surely messages should be sent in the background rather than locking the UI synchronously --Matthew
        sending: false // true when a message is being sent. It helps to disable the UI when a process is running
    };
    $scope.members = {};
    $scope.autoCompleting = false;
    $scope.autoCompleteIndex = 0;    
    $scope.autoCompleteOriginal = "";

    $scope.imageURLToSend = "";
    $scope.userIDToInvite = "";
    
    var scrollToBottom = function() {
        console.log("Scrolling to bottom");
        $timeout(function() {
            var objDiv = document.getElementById("messageTableWrapper");
            objDiv.scrollTop = objDiv.scrollHeight;
        }, 0);
    };

    $scope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
        if (isLive && event.room_id === $scope.room_id) {
            scrollToBottom();
            
            if (window.Notification) {
                // Show notification when the user is idle
                if (matrixService.presence.offline === mPresence.getState()) {
                    var notification = new window.Notification(
                        ($scope.members[event.user_id].displayname || event.user_id) +
                        " (" + ($scope.room_alias || $scope.room_id) + ")", // FIXME: don't leak room_ids here
                    {
                        "body": event.content.body,
                        "icon": $scope.members[event.user_id].avatar_url
                    });
                    $timeout(function() {
                        notification.close();
                    }, 5 * 1000);
                }
            }
        }
    });
    
    $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
        if (isLive) {
            updateMemberList(event);
        }
    });
    
    $scope.$on(eventHandlerService.PRESENCE_EVENT, function(ngEvent, event, isLive) {
        if (isLive) {
            updatePresence(event);
        }
    });
    
    $scope.$on(eventHandlerService.POWERLEVEL_EVENT, function(ngEvent, event, isLive) {
        if (isLive && event.room_id === $scope.room_id) {
            for (var user_id in event.content) {
                updateUserPowerLevel(user_id);
            }
        }
    });

    $scope.memberCount = function() {
        return Object.keys($scope.members).length;
    };
    
    $scope.paginateMore = function() {
        if ($scope.state.can_paginate) {
            // console.log("Paginating more.");
            paginate(MESSAGES_PER_PAGINATION);
        }
    };

    var paginate = function(numItems) {
        // console.log("paginate " + numItems);
        if ($scope.state.paginating || !$scope.room_id) {
            return;
        }
        else {
            $scope.state.paginating = true;
        }
        // console.log("paginateBackMessages from " + $scope.state.earliest_token + " for " + numItems);
        var originalTopRow = $("#messageTable>tbody>tr:first")[0];
        matrixService.paginateBackMessages($scope.room_id, $scope.state.earliest_token, numItems).then(
            function(response) {
                eventHandlerService.handleEvents(response.data.chunk, false);
                $scope.state.earliest_token = response.data.end;
                if (response.data.chunk.length < MESSAGES_PER_PAGINATION) {
                    // no more messages to paginate. this currently never gets turned true again, as we never
                    // expire paginated contents in the current implementation.
                    $scope.state.can_paginate = false;
                }
                
                $scope.state.paginating = false;
                
                var wrapper = $("#messageTableWrapper")[0];
                var table = $("#messageTable")[0];
                // console.log("wrapper height=" + wrapper.clientHeight + ", table scrollHeight=" + table.scrollHeight);
                
                if ($scope.state.can_paginate) {
                    // check we don't have to pull in more messages
                    // n.b. we dispatch through a timeout() to allow the digest to run otherwise the .height methods are stale
                    $timeout(function() {
                        if (table.scrollHeight < wrapper.clientHeight) {
                            paginate(MESSAGES_PER_PAGINATION);
                            scrollToBottom();                            
                        }
                    }, 0);
                }
                
                if ($scope.state.first_pagination) {
                    scrollToBottom();
                    $scope.state.first_pagination = false;
                }
                else {
                    // lock the scroll position
                    $timeout(function() {
                        // FIXME: this risks a flicker before the scrollTop is actually updated, but we have to
                        // dispatch it into a function in order to first update the layout.  The right solution
                        // might be to implement it as a directive, more like
                        // http://stackoverflow.com/questions/23736647/how-to-retain-scroll-position-of-ng-repeat-in-angularjs
                        // however, this specific solution breaks because it measures the rows height before
                        // the contents are interpolated.
                        wrapper.scrollTop = originalTopRow ? (originalTopRow.offsetTop + wrapper.scrollTop) : 0;
                    }, 0);
                }
            },
            function(error) {
                console.log("Failed to paginateBackMessages: " + JSON.stringify(error));
                $scope.state.paginating = false;
            }
        );
    };

    var updateMemberList = function(chunk) {
        if (chunk.room_id != $scope.room_id) return;

        // Ignore banned people
        if ("ban" === chunk.membership) {
            return;
        }

        // set target_user_id to keep things clear
        var target_user_id = chunk.state_key;

        var isNewMember = !(target_user_id in $scope.members);
        if (isNewMember) {
            // FIXME: why are we copying these fields around inside chunk?
            if ("presence" in chunk.content) {
                chunk.presence = chunk.content.presence;
            }
            if ("last_active_ago" in chunk.content) {
                chunk.last_active_ago = chunk.content.last_active_ago;
                $scope.now = new Date().getTime();
                chunk.last_updated = $scope.now;
            }
            if ("displayname" in chunk.content) {
                chunk.displayname = chunk.content.displayname;
            }
            if ("avatar_url" in chunk.content) {
                chunk.avatar_url = chunk.content.avatar_url;
            }
            $scope.members[target_user_id] = chunk;   

            if (target_user_id in $rootScope.presence) {
                updatePresence($rootScope.presence[target_user_id]);
            }
        }
        else {
            // selectively update membership and presence else it will nuke the picture and displayname too :/
            var member = $scope.members[target_user_id];
            member.membership = chunk.content.membership;
            if ("presence" in chunk.content) {
                member.presence = chunk.content.presence;
            }
            if ("last_active_ago" in chunk.content) {
                member.last_active_ago = chunk.content.last_active_ago;
                $scope.now = new Date().getTime();
                member.last_updated = $scope.now;
            }
        }
    };
    
    var updateMemberListPresenceAge = function() {
        $scope.now = new Date().getTime();
        // TODO: don't bother polling every 5s if we know none of our counters are younger than 1 minute
        $timeout(updateMemberListPresenceAge, 5 * 1000);
    };

    var updatePresence = function(chunk) {
        if (!(chunk.content.user_id in $scope.members)) {
            console.log("updatePresence: Unknown member for chunk " + JSON.stringify(chunk));
            return;
        }
        var member = $scope.members[chunk.content.user_id];

        // XXX: why not just pass the chunk straight through?
        if ("presence" in chunk.content) {
            member.presence = chunk.content.presence;
        }

        if ("last_active_ago" in chunk.content) {
            member.last_active_ago = chunk.content.last_active_ago;
            $scope.now = new Date().getTime();
            member.last_updated = $scope.now;
        }

        // this may also contain a new display name or avatar url, so check.
        if ("displayname" in chunk.content) {
            member.displayname = chunk.content.displayname;
        }

        if ("avatar_url" in chunk.content) {
            member.avatar_url = chunk.content.avatar_url;
        }
    };

    var updateUserPowerLevel = function(user_id) {
        var member = $scope.members[user_id];
        if (member) {
            member.powerLevel = matrixService.getUserPowerLevel($scope.room_id, user_id);
        }
    }

    $scope.send = function() {
        if ($scope.textInput === "") {
            return;
        }

        $scope.state.sending = true;
        
        var promise;
        
        // Check for IRC style commands first
        if ($scope.textInput.indexOf("/") === 0) {
            var args = $scope.textInput.split(' ');
            var cmd = args[0];
            
            switch (cmd) {
                case "/me":
                    var emoteMsg = args.slice(1).join(' ');
                    promise = matrixService.sendEmoteMessage($scope.room_id, emoteMsg);
                    break;
                    
                case "/nick":
                    // Change user display name
                    if (2 === args.length) {
                        promise = matrixService.setDisplayName(args[1]);
                    }
                    break;
                    
                case "/ban":
                    // Ban the user id from the room
                    if (2 <= args.length) {
                        // TODO: The user may have entered the display name
                        // Need display name -> user_id resolution. Pb: how to manage user with same display names?
                        var user_id = args[1];

                        // Does the user provide a reason?
                        if (3 <= args.length) {
                            var reason = args.slice(2).join(' ');
                        }
                        promise = matrixService.ban($scope.room_id, user_id, reason);
                    }
                    break;
                    
                case "/op":
                    // Define the power level of an user
                    if (3 === args.length) {
                        var user_id = args[1];
                        var powerLevel = parseInt(args[2]);
                        promise = matrixService.setUserPowerLevel($scope.room_id, user_id, powerLevel);
                    }
                    break;
                    
                case "/deop":
                    // Reset the power level of an user
                    if (2 === args.length) {
                        var user_id = args[1];
                        promise = matrixService.setUserPowerLevel($scope.room_id, user_id, undefined);
                    }
                    break;
            }
        }
        else {
            // Send the text message
            promise = matrixService.sendTextMessage($scope.room_id, $scope.textInput);
        }
        
        promise.then(
            function() {
                console.log("Request successfully sent");
                $scope.textInput = "";
                $scope.state.sending = false;
            },
            function(error) {
                $scope.feedback = "Request failed: " + error.data.error;
                $scope.state.sending = false;
            });
    };

    $scope.onInit = function() {
        console.log("onInit");

        // Does the room ID provided in the URL?
        var room_id_or_alias;
        if ($routeParams.room_id_or_alias) {
            room_id_or_alias = decodeURIComponent($routeParams.room_id_or_alias);
        }

        if (room_id_or_alias && '!' === room_id_or_alias[0]) {
            // Yes. We can go on right now
            $scope.room_id = room_id_or_alias;
            $scope.room_alias = matrixService.getRoomIdToAliasMapping($scope.room_id);
            onInit2();
        }
        else {
            // No. The URL contains the room alias. Get this alias.
            if (room_id_or_alias) {
                // The room alias was passed urlencoded, use it as is
                $scope.room_alias = room_id_or_alias;
            }
            else  {
                // Else get the room alias by hand from the URL
                // ie: extract #public:localhost:8080 from http://127.0.0.1:8000/#/room/#public:localhost:8080
                if (3 === location.hash.split("#").length) {
                    $scope.room_alias = "#" + location.hash.split("#")[2];
                }
                else {
                    // In case of issue, go to the default page
                    console.log("Error: cannot extract room alias");
                    $location.url("/");
                    return;
                }
            }
            
            // Need a room ID required in Matrix API requests
            console.log("Resolving alias: " + $scope.room_alias);
            matrixService.resolveRoomAlias($scope.room_alias).then(function(response) {
                $scope.room_id = response.data.room_id;
                console.log("   -> Room ID: " + $scope.room_id);

                // Now, we can go on
                onInit2();
            },
            function () {
                // In case of issue, go to the default page
                console.log("Error: cannot resolve room alias");
                $location.url("/");
            });
        }
    };
    
    var onInit2 = function() {
        console.log("onInit2");
        
        // Make sure the initialSync has been before going further
        eventHandlerService.waitForInitialSyncCompletion().then(
            function() {
                
                var needsToJoin = true;
                
                // The room members is available in the data fetched by initialSync
                if ($rootScope.events.rooms[$scope.room_id]) {
                    var members = $rootScope.events.rooms[$scope.room_id].members;

                    // Update the member list
                    for (var i in members) {
                        var member = members[i];
                        updateMemberList(member);
                    }

                    // Check if the user has already join the room
                    if ($scope.state.user_id in members) {
                        if ("join" === members[$scope.state.user_id].membership) {
                            needsToJoin = false;
                        }
                    }
                }
                
                // Do we to join the room before starting?
                if (needsToJoin) {
                    matrixService.join($scope.room_id).then(
                        function() {
                            console.log("Joined room "+$scope.room_id);
                            onInit3();
                        },
                        function(reason) {
                            console.log("Can't join room: " + JSON.stringify(reason));
                            $scope.feedback = "You do not have permission to join this room";
                        });
                }
                else {
                    onInit3();
                }
            }
        );
    };

    var onInit3 = function() {
        console.log("onInit3");
        
        // TODO: We should be able to keep them
        eventHandlerService.resetRoomMessages($scope.room_id); 

        // Make recents highlight the current room
        $scope.recentsSelectedRoomID = $scope.room_id;

		// Get the up-to-date the current member list
        matrixService.getMemberList($scope.room_id).then(
            function(response) {
                for (var i = 0; i < response.data.chunk.length; i++) {
                    var chunk = response.data.chunk[i];
                    updateMemberList(chunk);

                    // Add his power level
                    updateUserPowerLevel(chunk.user_id);
                }

                // Arm list timing update timer
                updateMemberListPresenceAge();
            },
            function(error) {
                $scope.feedback = "Failed get member list: " + error.data.error;
            }
        );

        paginate(MESSAGES_PER_PAGINATION);
    }; 
    
    $scope.inviteUser = function(user_id) {
        
        matrixService.invite($scope.room_id, user_id).then(
            function() {
                console.log("Invited.");
                $scope.feedback = "Invite sent successfully";
            },
            function(reason) {
                $scope.feedback = "Failure: " + reason;
            });
    };

    $scope.leaveRoom = function() {
        
        matrixService.leave($scope.room_id).then(
            function(response) {
                console.log("Left room ");
                $location.url("home");
            },
            function(error) {
                $scope.feedback = "Failed to leave room: " + error.data.error;
            });
    };

    $scope.sendImage = function(url, body) {
        $scope.state.sending = true;

        matrixService.sendImageMessage($scope.room_id, url, body).then(
            function() {
                console.log("Image sent");
                $scope.state.sending = false;
            },
            function(error) {
                $scope.feedback = "Failed to send image: " + error.data.error;
                $scope.state.sending = false;
            });
    };
    
    $scope.imageFileToSend;
    $scope.$watch("imageFileToSend", function(newValue, oldValue) {
        if ($scope.imageFileToSend) {

            $scope.state.sending = true;

            // Upload this image with its thumbnail to Internet
            mFileUpload.uploadImageAndThumbnail($scope.imageFileToSend, THUMBNAIL_SIZE).then(
                function(imageMessage) {
                    // imageMessage is complete message structure, send it as is
                    matrixService.sendMessage($scope.room_id, undefined, imageMessage).then(
                        function() {
                            console.log("Image message sent");
                            $scope.state.sending = false;
                        },
                        function(error) {
                            $scope.feedback = "Failed to send image message: " + error.data.error;
                            $scope.state.sending = false;
                        });
                },
                function(error) {
                    $scope.feedback = "Can't upload image";
                    $scope.state.sending = false;
                }
            );
        }
    });
    
    $scope.loadMoreHistory = function() {
        paginate(MESSAGES_PER_PAGINATION);
    };

    $scope.startVoiceCall = function() {
        var call = new MatrixCall($scope.room_id);
        call.onError = $rootScope.onCallError;
        call.onHangup = $rootScope.onCallHangup;
        call.placeCall();
        $rootScope.currentCall = call;
    }

}]);
