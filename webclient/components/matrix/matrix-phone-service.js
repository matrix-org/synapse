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

    matrixPhoneService.callPlaced = function(call) {
        matrixPhoneService.allCalls[call.call_id] = call;
    };

    $rootScope.$on(eventHandlerService.CALL_EVENT, function(ngEvent, event, isLive) {
        if (!isLive) return; // until matrix supports expiring messages
        if (event.user_id == matrixService.config().user_id) return;
        var msg = event.content;
        if (event.type == 'm.call.invite') {
            var MatrixCall = $injector.get('MatrixCall');
            var call = new MatrixCall(event.room_id);
            call.call_id = msg.call_id;
            call.initWithInvite(msg);
            matrixPhoneService.allCalls[call.call_id] = call;

            // Were we trying to call that user (room)?
            var existingCall;
            var callIds = Object.keys(matrixPhoneService.allCalls);
            for (var i = 0; i < callIds.length; ++i) {
                var thisCallId = callIds[i];
                var thisCall = matrixPhoneService.allCalls[thisCallId];

                if (call.room_id == thisCall.room_id && thisCall.direction == 'outbound'
                     && (thisCall.state == 'wait_local_media' || thisCall.state == 'invite_sent' || thisCall.state == 'create_offer')) {
                    existingCall = thisCall;
                    break;
                }
            }

            if (existingCall) {
                if (existingCall.call_id < call.call_id) {
                    console.log("Glare detected: rejecting incoming call "+call.call_id+" and keeping outgoing call "+existingCall.call_id);
                    call.hangup();
                } else {
                    console.log("Glare detected: answering incoming call "+call.call_id+" and canceling outgoing call "+existingCall.call_id);
                    existingCall.replacedBy(call);
                    call.answer();
                    $rootScope.$broadcast(matrixPhoneService.REPLACED_CALL_EVENT, existingCall, call);
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
        } else if (event.type == 'm.call.candidate') {
            var call = matrixPhoneService.allCalls[msg.call_id];
            if (!call) {
                console.log("Got candidate for unknown call ID "+msg.call_id);
                return;
            }
            call.gotRemoteIceCandidate(msg.candidate);
        } else if (event.type == 'm.call.hangup') {
            var call = matrixPhoneService.allCalls[msg.call_id];
            if (!call) {
                console.log("Got hangup for unknown call ID "+msg.call_id);
                return;
            }
            call.onHangupReceived();
            delete(matrixPhoneService.allCalls[msg.call_id]);
        }
    });
    
    return matrixPhoneService;
}]);
