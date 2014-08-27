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

angular.module('MatrixCall', [])
.factory('MatrixCall', ['matrixService', 'matrixPhoneService', function MatrixCallFactory(matrixService, matrixPhoneService) {
    var MatrixCall = function(room_id) {
        this.room_id = room_id;
        this.call_id = "c" + new Date().getTime();
    }

    navigator.getUserMedia = navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia;

    window.RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;

    MatrixCall.prototype.placeCall = function() {
        self = this;
        matrixPhoneService.callPlaced(this);
        navigator.getUserMedia({audio: true, video: false}, function(s) { self.gotUserMedia(s); }, function(e) { self.getUserMediaFailed(e); });
    };

    MatrixCall.prototype.gotUserMedia = function(stream) {
        this.peerConn = new window.RTCPeerConnection({"iceServers":[{"urls":"stun:stun.l.google.com:19302"}]})
        this.peerConn.addStream(stream);
        self = this;
        this.peerConn.onicecandidate = function(c) { self.gotLocalIceCandidate(c); };
        this.peerConn.createOffer(function(d) {
            self.gotLocalOffer(d);
        }, function(e) {
            self.getLocalOfferFailed(e);
        });
    };

    MatrixCall.prototype.gotLocalIceCandidate = function(event) {
        console.trace(event);
        if (event.candidate) {
            var content = {
                msgtype: "m.call.candidate",
                version: 0,
                call_id: this.call_id,
                candidate: event.candidate
            };
            matrixService.sendMessage(this.room_id, undefined, content).then(this.messageSent, this.messageSendFailed);
        }
    }

    MatrixCall.prototype.gotRemoteIceCandidate = function(cand) {
        this.peerConn.addIceCandidate(cand);
    };

    MatrixCall.prototype.gotLocalOffer = function(description) {
        console.trace(description);
        this.peerConn.setLocalDescription(description);

        var content = {
            msgtype: "m.call.invite",
            version: 0,
            call_id: this.call_id,
            offer: description
        };
        matrixService.sendMessage(this.room_id, undefined, content).then(this.messageSent, this.messageSendFailed);
    };

    MatrixCall.prototype.messageSent = function() {
    };
    
    MatrixCall.prototype.messageSendFailed = function(error) {
    };

    MatrixCall.prototype.getLocalOfferFailed = function(error) {
        this.onError("Failed to start audio for call!");
    };

    MatrixCall.prototype.getUserMediaFailed = function() {
        this.onError("Couldn't start capturing audio! Is your microphone set up?");
    };
    
    return MatrixCall;
}]);
