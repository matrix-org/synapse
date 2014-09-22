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

'use strict';

angular.module('matrixPhoneService', [])
.factory('matrixPhoneService', ['$rootScope', '$injector', 'matrixService', 'eventHandlerService', function MatrixPhoneService($rootScope, $injector, matrixService, eventHandlerService) {
    var matrixPhoneService = function() {
    };

    matrixPhoneService.INCOMING_CALL_EVENT = "INCOMING_CALL_EVENT";
    matrixPhoneService.REPLACED_CALL_EVENT = "REPLACED_CALL_EVENT";
    matrixPhoneService.allCalls = {};
    // a place to save candidates that come in for calls we haven't got invites for yet (when paginating backwards)
    matrixPhoneService.candidatesByCall = {};

    matrixPhoneService.callPlaced = function(call) {
        matrixPhoneService.allCalls[call.call_id] = call;
    };

    $rootScope.$on(eventHandlerService.CALL_EVENT, function(ngEvent, event, isLive) {
        if (event.user_id == matrixService.config().user_id) return;

        var msg = event.content;

        if (event.type == 'm.call.invite') {
            if (event.age == undefined || msg.lifetime == undefined) {
                // if the event doesn't have either an age (the HS is too old) or a lifetime
                // (the sending client was too old when it sent it) then fall back to old behaviour
                if (!isLive) return; // until matrix supports expiring messages
            }

            if (event.age > msg.lifetime) {
                console.log("Ignoring expired call event of type "+event.type);
                return;
            }

            var call = undefined;
            if (!isLive) {
                // if this event wasn't live then this call may already be over
                call = matrixPhoneService.allCalls[msg.call_id];
                if (call && call.state == 'ended') {
                    return;
                }
            }

            var MatrixCall = $injector.get('MatrixCall');
            var call = new MatrixCall(event.room_id);

            if (!isWebRTCSupported()) {
                console.log("Incoming call ID "+msg.call_id+" but this browser doesn't support WebRTC");
                // don't hang up the call: there could be other clients connected that do support WebRTC and declining the
                // the call on their behalf would be really annoying.
                // instead, we broadcast a fake call event with a non-functional call object
                $rootScope.$broadcast(matrixPhoneService.INCOMING_CALL_EVENT, call);
                return;
            }

            call.call_id = msg.call_id;
            call.initWithInvite(event);
            matrixPhoneService.allCalls[call.call_id] = call;

            // if we stashed candidate events for that call ID, play them back now
            if (!isLive && matrixPhoneService.candidatesByCall[call.call_id] != undefined) {
                for (var i = 0; i < matrixPhoneService.candidatesByCall[call.call_id].length; ++i) {
                    call.gotRemoteIceCandidate(matrixPhoneService.candidatesByCall[call.call_id][i]);
                }
            }

            // Were we trying to call that user (room)?
            var existingCall;
            var callIds = Object.keys(matrixPhoneService.allCalls);
            for (var i = 0; i < callIds.length; ++i) {
                var thisCallId = callIds[i];
                var thisCall = matrixPhoneService.allCalls[thisCallId];

                if (call.room_id == thisCall.room_id && thisCall.direction == 'outbound'
                     && (thisCall.state == 'wait_local_media' || thisCall.state == 'create_offer' || thisCall.state == 'invite_sent')) {
                    existingCall = thisCall;
                    break;
                }
            }

            if (existingCall) {
                // If we've only got to wait_local_media or create_offer and we've got an invite,
                // pick the incoming call because we know we haven't sent our invite yet
                // otherwise, pick whichever call has the lowest call ID (by string comparison)
                if (existingCall.state == 'wait_local_media' || existingCall.state == 'create_offer' || existingCall.call_id > call.call_id) {
                    console.log("Glare detected: answering incoming call "+call.call_id+" and canceling outgoing call "+existingCall.call_id);
                    existingCall.replacedBy(call);
                    call.answer();
                    $rootScope.$broadcast(matrixPhoneService.REPLACED_CALL_EVENT, existingCall, call);
                } else {
                    console.log("Glare detected: rejecting incoming call "+call.call_id+" and keeping outgoing call "+existingCall.call_id);
                    call.hangup();
                }
            } else {
                $rootScope.$broadcast(matrixPhoneService.INCOMING_CALL_EVENT, call);
            }
        } else if (event.type == 'm.call.answer') {
            var call = matrixPhoneService.allCalls[msg.call_id];
            if (!call) {
                console.log("Got answer for unknown call ID "+msg.call_id);
                return;
            }
            call.receivedAnswer(msg);
        } else if (event.type == 'm.call.candidates') {
            var call = matrixPhoneService.allCalls[msg.call_id];
            if (!call && isLive) {
                console.log("Got candidates for unknown call ID "+msg.call_id);
                return;
            } else if (!call) {
                if (matrixPhoneService.candidatesByCall[msg.call_id] == undefined) {
                    matrixPhoneService.candidatesByCall[msg.call_id] = [];
                }
                matrixPhoneService.candidatesByCall[msg.call_id] = matrixPhoneService.candidatesByCall[msg.call_id].concat(msg.candidates);
            } else {
                for (var i = 0; i < msg.candidates.length; ++i) {
                    call.gotRemoteIceCandidate(msg.candidates[i]);
                }
            }
        } else if (event.type == 'm.call.hangup') {
            var call = matrixPhoneService.allCalls[msg.call_id];
            if (!call && isLive) {
                console.log("Got hangup for unknown call ID "+msg.call_id);
            } else if (!call) {
                // if not live, store the fact that the call has ended because we're probably getting events backwards so
                // the hangup will come before the invite
                var MatrixCall = $injector.get('MatrixCall');
                var call = new MatrixCall(event.room_id);
                call.call_id = msg.call_id;
                call.initWithHangup(event);
                matrixPhoneService.allCalls[msg.call_id] = call;
            } else {
                call.onHangupReceived(msg);
                delete(matrixPhoneService.allCalls[msg.call_id]);
            }
        }
    });
    
    return matrixPhoneService;
}]);
