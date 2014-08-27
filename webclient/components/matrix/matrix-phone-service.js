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

angular.module('matrixPhoneService', [])
.factory('matrixPhoneService', ['$rootScope', 'matrixService', 'MatrixCall', 'eventHandlerService', function MatrixCallFactory($rootScope, matrixService, MatrixCall, eventHandlerService) {
    var matrixPhoneService = function() {
    }

    matrixPhoneService.CALL_EVENT = "CALL_EVENT";
    matrixPhoneService.allCalls = {};

    MatrixCall.prototype.placeCall = function() {
        self = this;
        navigator.getUserMedia({audio: true, video: false}, function(s) { self.gotUserMedia(s); }, function(e) { self.getUserMediaFailed(e); });
    };
    
    matrixPhoneService.prototype.callPlaced = function(call) {
        matrixPhoneService.allCalls[call.call_id] = call;
    };

    $rootScope.$on(eventHandlerService.MSG_EVENT, function(ngEvent, event, isLive) {
        if (!isLive) return; // until matrix supports expiring messages
        if (event.user_id == matrixService.config().user_id) return;
        var msg = event.content;
        if (msg.msgtype == 'm.call.invite') {
            var call = new MatrixCall(event.room_id);
            call.call_id = msg.call_id;
            $rootScope.$broadcast(matrixPhoneService.CALL_EVENT, call);
            matrixPhoneService.allCalls[call.call_id] = call;
        } else if (msg.msgtype == 'm.call.candidate') {
            call = matrixPhoneService.allCalls[msg.call_id];
            if (!call) {
                console.trace("Got candidate for unknown call ID "+msg.call_id);
                return;
            }
            call.gotRemoteIceCandidate(msg.candidate);
        }
    });
    
    return matrixPhoneService;
}]);
