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

angular.module('RoomController', ['ngSanitize', 'matrixFilter', 'mFileInput'])
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
        first_pagination: true, // this is toggled off when the first pagination is done
        can_paginate: false, // this is toggled off when we are not ready yet to paginate or when we run out of items
        paginating: false, // used to avoid concurrent pagination requests pulling in dup contents
        stream_failure: undefined, // the response when the stream fails
        waiting_for_joined_event: false  // true when the join request is pending. Back to false once the corresponding m.room.member event is received
    };
    $scope.members = {};
    $scope.autoCompleting = false;
    $scope.autoCompleteIndex = 0;    
    $scope.autoCompleteOriginal = "";

    $scope.imageURLToSend = "";
    $scope.userIDToInvite = "";
    
    // vars and functions for updating the topic
    $scope.topic = {
        isEditing: false,
        newTopicText: "",
        editTopic: function() {
            if ($scope.topic.isEditing) {
                console.log("Warning: Already editing topic.");
                return;
            }
            var topicEvent = $rootScope.events.rooms[$scope.room_id]['m.room.topic'];
            if (topicEvent) {
                $scope.topic.newTopicText = topicEvent.content.topic;
            }
            else {
                $scope.topic.newTopicText = "";
            }
            
            // Force focus to the input
            $timeout(function() {
                angular.element('.roomTopicInput').focus(); 
            }, 0);
            
            $scope.topic.isEditing = true;
        },
        updateTopic: function() {
            console.log("Updating topic to "+$scope.topic.newTopicText);
            matrixService.setTopic($scope.room_id, $scope.topic.newTopicText);
            $scope.topic.isEditing = false;
        },
        cancelEdit: function() {
            $scope.topic.isEditing = false;
        }
    };
    
    
    
    
    var scrollToBottom = function(force) {
        console.log("Scrolling to bottom");
        
        // Do not autoscroll to the bottom to display the new event if the user is not at the bottom.
        // Exception: in case where the event is from the user, we want to force scroll to the bottom
        var objDiv = document.getElementById("messageTableWrapper");
        if ((objDiv.offsetHeight + objDiv.scrollTop >= objDiv.scrollHeight) || force) {
            
            $timeout(function() {
                objDiv.scrollTop = objDiv.scrollHeight;
            }, 0);
        }
    };

    $scope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
        if (isLive && event.room_id === $scope.room_id) {
            
            scrollToBottom();

            if (window.Notification) {
                // Show notification when the window is hidden, or the user is idle
                if (document.hidden || matrixService.presence.unavailable === mPresence.getState()) {
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
            if ($scope.state.waiting_for_joined_event) {
                // The user has successfully joined the room, we can getting data for this room
                $scope.state.waiting_for_joined_event = false;
                onInit3();
            }
            else {
                scrollToBottom();
                updateMemberList(event); 
            }
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
        
        console.log("paginateBackMessages from " + $rootScope.events.rooms[$scope.room_id].pagination.earliest_token + " for " + numItems);
        var originalTopRow = $("#messageTable>tbody>tr:first")[0];
        
        // Paginate events from the point in cache
        matrixService.paginateBackMessages($scope.room_id, $rootScope.events.rooms[$scope.room_id].pagination.earliest_token, numItems).then(
            function(response) {

                eventHandlerService.handleRoomMessages($scope.room_id, response.data, false);
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


        // set target_user_id to keep things clear
        var target_user_id = chunk.state_key;

        var isNewMember = !(target_user_id in $scope.members);
        if (isNewMember) {
            
            // Ignore banned and kicked (leave) people
            if ("ban" === chunk.membership || "leave" === chunk.membership) {
                return;
            }
        
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
            
            // Remove banned and kicked (leave) people
            if ("ban" === chunk.membership || "leave" === chunk.membership) {
                delete $scope.members[target_user_id];
                return;
            }
            
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
            
            normaliseMembersPowerLevels();
        }
    };

    // Normalise users power levels so that the user with the higher power level
    // will have a bar covering 100% of the width of his avatar
    var normaliseMembersPowerLevels = function() {
        // Find the max power level
        var maxPowerLevel = 0;
        for (var i in $scope.members) {
            var member = $scope.members[i];
            if (member.powerLevel) {
                maxPowerLevel = Math.max(maxPowerLevel, member.powerLevel);
            }
        }

        // Normalized them on a 0..100% scale to be use in css width
        if (maxPowerLevel) {
            for (var i in $scope.members) {
                var member = $scope.members[i];
                member.powerLevelNorm = (member.powerLevel * 100) / maxPowerLevel;
            }
        }
    };

    $scope.send = function() {
        if ($scope.textInput === "") {
            return;
        }
        
        scrollToBottom(true);
        
        var promise;
        var cmd;
        var args;
        var echo = false;
        
        // Check for IRC style commands first
        var line = $scope.textInput;
        
        // trim any trailing whitespace, as it can confuse the parser for IRC-style commands
        line = line.replace(/\s+$/, "");
        
        if (line[0] === "/" && line[1] !== "/") {
            var bits = line.match(/^(\S+?)( +(.*))?$/);
            cmd = bits[1];
            args = bits[3];
            
            console.log("cmd: " + cmd + ", args: " + args);
            
            switch (cmd) {
                case "/me":
                    promise = matrixService.sendEmoteMessage($scope.room_id, args);
                    echo = true;
                    break;
                    
                case "/nick":
                    // Change user display name
                    if (args) {
                        promise = matrixService.setDisplayName(args);                     
                    }
                    else {
                        $scope.feedback = "Usage: /nick <display_name>";
                    }
                    break;

                case "/join":
                    // Join a room
                    if (args) {
                        var matches = args.match(/^(\S+)$/);
                        if (matches) {
                            var room_alias = matches[1];
                            if (room_alias.indexOf(':') == -1) {
                                // FIXME: actually track the :domain style name of our homeserver
                                // with or without port as is appropriate and append it at this point
                            }
                            
                            var room_id = matrixService.getAliasToRoomIdMapping(room_alias);
                            console.log("joining " + room_alias + " id=" + room_id);
                            if ($rootScope.events.rooms[room_id]) {
                                // don't send a join event for a room you're already in.
                                $location.url("room/" + room_alias);
                            }
                            else {
                                promise = matrixService.joinAlias(room_alias).then(
                                    function(response) {
                                        $location.url("room/" + room_alias);
                                    },
                                    function(error) {
                                        $scope.feedback = "Can't join room: " + JSON.stringify(error.data);
                                    }
                                );
                            }
                        }
                    }
                    else {
                        $scope.feedback = "Usage: /join <room_alias>";
                    }
                    break;
                    
                case "/kick":
                    // Kick a user from the room with an optional reason
                    if (args) {
                        var matches = args.match(/^(\S+?)( +(.*))?$/);
                        if (matches) {
                            promise = matrixService.kick($scope.room_id, matches[1], matches[3]);
                        }
                    }

                    if (!promise) {
                        $scope.feedback = "Usage: /kick <userId> [<reason>]";
                    }
                    break;

                case "/ban":
                    // Ban a user from the room with an optional reason
                    if (args) {
                        var matches = args.match(/^(\S+?)( +(.*))?$/);
                        if (matches) {
                            promise = matrixService.ban($scope.room_id, matches[1], matches[3]);
                        }
                    }
                    
                    if (!promise) {
                        $scope.feedback = "Usage: /ban <userId> [<reason>]";
                    }
                    break;

                case "/unban":
                    // Unban a user from the room
                    if (args) {
                        var matches = args.match(/^(\S+)$/);
                        if (matches) {
                            // Reset the user membership to "leave" to unban him
                            promise = matrixService.unban($scope.room_id, matches[1]);
                        }
                    }
                    
                    if (!promise) {
                        $scope.feedback = "Usage: /unban <userId>";
                    }
                    break;
                    
                case "/op":
                    // Define the power level of a user
                    if (args) {
                        var matches = args.match(/^(\S+?)( +(\d+))?$/);
                        var powerLevel = 50; // default power level for op
                        if (matches) {
                            var user_id = matches[1];
                            if (matches.length === 4 && undefined !== matches[3]) {
                                powerLevel = parseInt(matches[3]);
                            }
                            if (powerLevel !== NaN) {
                                promise = matrixService.setUserPowerLevel($scope.room_id, user_id, powerLevel);
                            }
                        }
                    }
                    
                    if (!promise) {
                        $scope.feedback = "Usage: /op <userId> [<power level>]";
                    }
                    break;
                    
                case "/deop":
                    // Reset the power level of a user
                    if (args) {
                        var matches = args.match(/^(\S+)$/);
                        if (matches) {
                            promise = matrixService.setUserPowerLevel($scope.room_id, args, undefined);
                        }
                    }
                    
                    if (!promise) {
                        $scope.feedback = "Usage: /deop <userId>";
                    }
                    break;
                
                default:
                    $scope.feedback = ("Unrecognised IRC-style command: " + cmd);
                    break;
            }
        }
        
        // By default send this as a message unless it's an IRC-style command
        if (!promise && !cmd) {
            // Make the request
            promise = matrixService.sendTextMessage($scope.room_id, line);
            echo = true;
        }
        
        if (echo) {
            // Echo the message to the room
            // To do so, create a minimalist fake text message event and add it to the in-memory list of room messages
            var echoMessage = {
                content: {
                    body: (cmd === "/me" ? args : line),
                    hsob_ts: new Date().getTime(), // fake a timestamp
                    msgtype: (cmd === "/me" ? "m.emote" : "m.text"),
                },
                room_id: $scope.room_id,
                type: "m.room.message",
                user_id: $scope.state.user_id,
                echo_msg_state: "messagePending"     // Add custom field to indicate the state of this fake message to HTML
            };

            $scope.textInput = "";
            $rootScope.events.rooms[$scope.room_id].messages.push(echoMessage);
            scrollToBottom();
        }

        if (promise) {
            // Reset previous feedback
            $scope.feedback = "";

            promise.then(
                function(response) {
                    console.log("Request successfully sent");
                    if (echo) {
                        // Mark this fake message event with its allocated event_id
                        // When the true message event will come from the events stream (in handleMessage),
                        // we will be able to replace the fake one by the true one
                        echoMessage.event_id = response.data.event_id;
                    }
                    else {
                        $scope.textInput = "";
                    }         
                },
                function(error) {
                    $scope.feedback = "Request failed: " + error.data.error;

                    if (echoMessage) {
                        // Mark the message as unsent for the rest of the page life
                        echoMessage.content.hsob_ts = "Unsent";
                        echoMessage.echo_msg_state = "messageUnSent";
                    }
                });
        }
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
                    $scope.state.waiting_for_joined_event = true;
                    matrixService.join($scope.room_id).then(
                        function() {
                            // onInit3 will be called once the joined m.room.member event is received from the events stream
                            // This avoids to get the joined information twice in parallel:
                            //    - one from the events stream
                            //    - one from the pagination because the pagination window covers this event ts
                            console.log("Joined room "+$scope.room_id);
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

                // Start pagination
                $scope.state.can_paginate = true;
                paginate(MESSAGES_PER_PAGINATION);
            },
            function(error) {
                $scope.feedback = "Failed get member list: " + error.data.error;
            }
        );
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
        scrollToBottom(true);
        
        matrixService.sendImageMessage($scope.room_id, url, body).then(
            function() {
                console.log("Image sent");
            },
            function(error) {
                $scope.feedback = "Failed to send image: " + error.data.error;
            });
    };
    
    $scope.imageFileToSend;
    $scope.$watch("imageFileToSend", function(newValue, oldValue) {
        if ($scope.imageFileToSend) {
            // Upload this image with its thumbnail to Internet
            mFileUpload.uploadImageAndThumbnail($scope.imageFileToSend, THUMBNAIL_SIZE).then(
                function(imageMessage) {
                    // imageMessage is complete message structure, send it as is
                    matrixService.sendMessage($scope.room_id, undefined, imageMessage).then(
                        function() {
                            console.log("Image message sent");
                        },
                        function(error) {
                            $scope.feedback = "Failed to send image message: " + error.data.error;
                        });
                },
                function(error) {
                    $scope.feedback = "Can't upload image";
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
        call.placeCall({audio: true, video: false});
        $rootScope.currentCall = call;
    };

    $scope.startVideoCall = function() {
        var call = new MatrixCall($scope.room_id);
        call.onError = $rootScope.onCallError;
        call.onHangup = $rootScope.onCallHangup;
        call.placeCall({audio: true, video: true});
        $rootScope.currentCall = call;
    };

}]);
