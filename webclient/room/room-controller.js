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
    var MESSAGES_PER_PAGINATION = 30;
    $scope.room_id = $routeParams.room_id;
    $scope.room_alias = matrixService.getRoomIdToAliasMapping($scope.room_id);
    $scope.state = {
        user_id: matrixService.config().user_id,
        events_from: "END", // when to start the event stream from.
        earliest_token: "END", // stores how far back we've paginated.
        can_paginate: true, // this is toggled off when we run out of items
        paginating: false, // used to avoid concurrent pagination requests pulling in dup contents
        stream_failure: undefined // the response when the stream fails
    };
    $scope.members = {};

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
        }
    });
    
    $scope.$on(eventHandlerService.MEMBER_EVENT, function(ngEvent, event, isLive) {
        updateMemberList(event);
    });
    
    $scope.$on(eventHandlerService.PRESENCE_EVENT, function(ngEvent, event, isLive) {
        updatePresence(event);
    });
    
    $scope.paginateMore = function() {
        if ($scope.state.can_paginate) {
            // console.log("Paginating more.");
            paginate(MESSAGES_PER_PAGINATION);
        }
    };
    
    var paginate = function(numItems) {
        // console.log("paginate " + numItems);
        if ($scope.state.paginating) {
            return;
        }
        else {
            $scope.state.paginating = true;
        }
        // console.log("paginateBackMessages from " + $scope.state.earliest_token + " for " + numItems);
        var originalTopRow = $("#messageTable>tbody>tr:first")[0];
        matrixService.paginateBackMessages($scope.room_id, $scope.state.earliest_token, numItems).then(
            function(response) {
                var firstPagination = !$scope.events.rooms[$scope.room_id];
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
                
                if (firstPagination) {
                    scrollToBottom();
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
        )
    };

    var updateMemberList = function(chunk) {
        var isNewMember = !(chunk.target_user_id in $scope.members);
        if (isNewMember) {
            // FIXME: why are we copying these fields around inside chunk?
            if ("state" in chunk.content) {
                chunk.presenceState = chunk.content.state; // why is this renamed?
            }
            if ("mtime_age" in chunk.content) {
                chunk.mtime_age = chunk.content.mtime_age;
            }
/*            
            // FIXME: once the HS reliably returns the displaynames & avatar_urls for both
            // local and remote users, we should use this rather than the evalAsync block
            // below
            if ("displayname" in chunk.content) {
                chunk.displayname = chunk.content.displayname;
            }
            if ("avatar_url" in chunk.content) {
                chunk.avatar_url = chunk.content.avatar_url;
            }
 */      
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
                            member.displayname = response.data.displayname;
                        }
                    }
                ); 
                matrixService.getProfilePictureUrl(chunk.target_user_id).then(
                    function(response) {
                         var member = $scope.members[chunk.target_user_id];
                         if (member !== undefined) {
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

        // XXX: why not just pass the chunk straight through?
        if ("state" in chunk.content) {
            member.presenceState = chunk.content.state;
        }

        if ("mtime_age" in chunk.content) {
            // FIXME: should probably keep updating mtime_age in realtime like FB does
            member.mtime_age = chunk.content.mtime_age;
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
}]);
