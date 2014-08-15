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

/*
This service manages where in the event stream the web client currently is and 
provides methods to resume/pause/stop the event stream. This service is not
responsible for parsing event data. For that, see the eventDataHandler.
*/
angular.module('eventStreamService', [])
.factory('eventStreamService', ['matrixService', function(matrixService) {
    var END = "END";
    var START = "START";
    var TIMEOUT_MS = 5000;
    
    var settings = {
        from: "END",
        to: undefined,
        limit: undefined,
        shouldPoll: true
    };
    
    // interrupts the stream. Only valid if there is a stream conneciton 
    // open.
    var interrupt = function(shouldPoll) {
        console.log("p[EventStream] interrupt("+shouldPoll+") "+
                    JSON.stringify(settings));
    };
    
    var saveStreamSettings = function() {
        localStorage.setItem("streamSettings", JSON.stringify(settings));
    };
    
    return {
        // resume the stream from whereever it last got up to. Typically used
        // when the page is opened.
        resume: function() {
            console.log("[EventStream] resume "+JSON.stringify(settings));
            // run the stream from the latest token
            return matrixService.getEventStream(settings.from, TIMEOUT_MS);
        },
        
        // pause the stream. Resuming it will continue from the current position
        pause: function() {
            console.log("[EventStream] pause "+JSON.stringify(settings));
            // kill any running stream
            interrupt(false);
            // save the latest token
            saveStreamSettings();
        },
        
        // stop the stream and wipe the position in the stream. Typically used
        // when logging out / logged out.
        stop: function() {
            console.log("[EventStream] stop "+JSON.stringify(settings));
            // kill any running stream
            interrupt(false);
            // clear the latest token
            settings.from = END;
            saveStreamSettings();
        }
    };

}]);
