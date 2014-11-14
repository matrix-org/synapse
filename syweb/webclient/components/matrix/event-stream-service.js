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

/*
This service manages where in the event stream the web client currently is,
repolling the event stream, and provides methods to resume/pause/stop the event 
stream. This service is not responsible for parsing event data. For that, see 
the eventHandlerService.
*/
angular.module('eventStreamService', [])
.factory('eventStreamService', ['$q', '$timeout', 'matrixService', 'eventHandlerService', function($q, $timeout, matrixService, eventHandlerService) {
    var END = "END";
    var SERVER_TIMEOUT_MS = 30000;
    var CLIENT_TIMEOUT_MS = 40000;
    var ERR_TIMEOUT_MS = 5000;
    
    var settings = {
        from: "END",
        to: undefined,
        limit: undefined,
        shouldPoll: true,
        isActive: false
    };
    
    // interrupts the stream. Only valid if there is a stream conneciton 
    // open.
    var interrupt = function(shouldPoll) {
        console.log("[EventStream] interrupt("+shouldPoll+") "+
                    JSON.stringify(settings));
        settings.shouldPoll = shouldPoll;
        settings.isActive = false;
    };
    
    var saveStreamSettings = function() {
        localStorage.setItem("streamSettings", JSON.stringify(settings));
    };

    var doEventStream = function(deferred) {
        settings.shouldPoll = true;
        settings.isActive = true;
        deferred = deferred || $q.defer();

        // run the stream from the latest token
        matrixService.getEventStream(settings.from, SERVER_TIMEOUT_MS, CLIENT_TIMEOUT_MS).then(
            function(response) {
                if (!settings.isActive) {
                    console.log("[EventStream] Got response but now inactive. Dropping data.");
                    return;
                }
                
                settings.from = response.data.end;
                
                console.log(
                    "[EventStream] Got response from "+settings.from+
                    " to "+response.data.end
                );
                eventHandlerService.handleEvents(response.data.chunk, true);
                
                deferred.resolve(response);
                
                if (settings.shouldPoll) {
                    $timeout(doEventStream, 0);
                }
                else {
                    console.log("[EventStream] Stopping poll.");
                }
            },
            function(error) {
                if (error.status === 403) {
                    settings.shouldPoll = false;
                }
                
                deferred.reject(error);
                
                if (settings.shouldPoll) {
                    $timeout(doEventStream, ERR_TIMEOUT_MS);
                }
                else {
                    console.log("[EventStream] Stopping polling.");
                }
            }
        );

        return deferred.promise;
    }; 

    var startEventStream = function() {
        settings.shouldPoll = true;
        settings.isActive = true;
        var deferred = $q.defer();

        // Initial sync: get all information and the last 30 messages of all rooms of the user
        // 30 messages should be enough to display a full page of messages in a room
        // without requiring to make an additional request
        matrixService.initialSync(30, false).then(
            function(response) {
                eventHandlerService.handleInitialSyncDone(response);

                // Start event streaming from that point
                settings.from = response.data.end;
                doEventStream(deferred);        
            },
            function(error) {
                $scope.feedback = "Failure: " + error.data;
            }
        );

        return deferred.promise;
    };
    
    return {
        // expose these values for testing
        SERVER_TIMEOUT: SERVER_TIMEOUT_MS,
        CLIENT_TIMEOUT: CLIENT_TIMEOUT_MS,
    
        // resume the stream from whereever it last got up to. Typically used
        // when the page is opened.
        resume: function() {
            if (settings.isActive) {
                console.log("[EventStream] Already active, ignoring resume()");
                return;
            }
        
            console.log("[EventStream] resume "+JSON.stringify(settings));
            return startEventStream();
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
