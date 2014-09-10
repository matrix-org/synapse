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
This service handles what should happen when you get an event. This service does
not care where the event came from, it only needs enough context to be able to 
process them. Events may be coming from the event stream, the REST API (via 
direct GETs or via a pagination stream API), etc.

Typically, this service will store events or broadcast them to any listeners
(e.g. controllers) via $broadcast. Alternatively, it may update the $rootScope
if typically all the $on method would do is update its own $scope.
*/
angular.module('eventHandlerService', [])
.factory('eventHandlerService', ['matrixService', '$rootScope', '$q', function(matrixService, $rootScope, $q) {
    var ROOM_CREATE_EVENT = "ROOM_CREATE_EVENT";
    var MSG_EVENT = "MSG_EVENT";
    var MEMBER_EVENT = "MEMBER_EVENT";
    var PRESENCE_EVENT = "PRESENCE_EVENT";
    var POWERLEVEL_EVENT = "POWERLEVEL_EVENT";
    var CALL_EVENT = "CALL_EVENT";
    var NAME_EVENT = "NAME_EVENT";

    var initialSyncDeferred = $q.defer();
    
    $rootScope.events = {
        rooms: {} // will contain roomId: { messages:[], members:{userid1: event} }
    };
    
    // used for dedupping events - could be expanded in future...
    // FIXME: means that we leak memory over time (along with lots of the rest
    // of the app, given we never try to reap memory yet)
    var eventMap = {};

    $rootScope.presence = {};
    
    var initRoom = function(room_id) {
        if (!(room_id in $rootScope.events.rooms)) {
            console.log("Creating new handler entry for " + room_id);
            $rootScope.events.rooms[room_id] = {};
            $rootScope.events.rooms[room_id].messages = [];
            $rootScope.events.rooms[room_id].members = {};

            // Pagination information
            $rootScope.events.rooms[room_id].pagination = {
                earliest_token: "END"   // how far back we've paginated
            }
        }
    };

    var resetRoomMessages = function(room_id) {
        if ($rootScope.events.rooms[room_id]) {
            $rootScope.events.rooms[room_id].messages = [];
        }
    };
    
    var handleRoomCreate = function(event, isLiveEvent) {
        initRoom(event.room_id);

        // For now, we do not use the event data. Simply signal it to the app controllers
        $rootScope.$broadcast(ROOM_CREATE_EVENT, event, isLiveEvent);
    };

    var handleRoomAliases = function(event, isLiveEvent) {
        matrixService.createRoomIdToAliasMapping(event.room_id, event.content.aliases[0]);
    };

    var handleMessage = function(event, isLiveEvent) {
        initRoom(event.room_id);
        
        if (isLiveEvent) {
            if (event.user_id === matrixService.config().user_id &&
                (event.content.msgtype === "m.text" || event.content.msgtype === "m.emote") ) {
                // assume we've already echoed it
                // FIXME: track events by ID and ungrey the right message to show it's been delivered
            }
            else {
                $rootScope.events.rooms[event.room_id].messages.push(event);
            }
        }
        else {
            $rootScope.events.rooms[event.room_id].messages.unshift(event);
        }
        
        // TODO send delivery receipt if isLiveEvent
        
        // $broadcast this, as controllers may want to do funky things such as
        // scroll to the bottom, etc which cannot be expressed via simple $scope
        // updates.
        $rootScope.$broadcast(MSG_EVENT, event, isLiveEvent);
    };
    
    var handleRoomMember = function(event, isLiveEvent) {
        initRoom(event.room_id);
        
        // if the server is stupidly re-relaying a no-op join, discard it.
        if (event.prev_content && 
            event.content.membership === "join" &&
            event.content.membership === event.prev_content.membership)
        {
            return;
        }
        
        // add membership changes as if they were a room message if something interesting changed
        if (event.content.prev !== event.content.membership) {
            if (isLiveEvent) {
                $rootScope.events.rooms[event.room_id].messages.push(event);
            }
            else {
                $rootScope.events.rooms[event.room_id].messages.unshift(event);
            }
        }
        
        $rootScope.events.rooms[event.room_id].members[event.state_key] = event;
        $rootScope.$broadcast(MEMBER_EVENT, event, isLiveEvent);
    };
    
    var handlePresence = function(event, isLiveEvent) {
        $rootScope.presence[event.content.user_id] = event;
        $rootScope.$broadcast(PRESENCE_EVENT, event, isLiveEvent);
    };
    
    var handlePowerLevels = function(event, isLiveEvent) {
        initRoom(event.room_id);

        // Keep the latest data. Do not care of events that come when paginating back
        if (!$rootScope.events.rooms[event.room_id][event.type] || isLiveEvent) {
            $rootScope.events.rooms[event.room_id][event.type] = event;
            $rootScope.$broadcast(POWERLEVEL_EVENT, event, isLiveEvent);   
        }
    };

    var handleRoomName = function(event, isLiveEvent) {
        console.log("handleRoomName " + isLiveEvent);

        initRoom(event.room_id);

        $rootScope.events.rooms[event.room_id][event.type] = event;
        $rootScope.$broadcast(NAME_EVENT, event, isLiveEvent);
    };
    
    // TODO: Can this just be a generic "I am a room state event, can haz store?"
    var handleRoomTopic = function(event, isLiveEvent) {
        console.log("handleRoomTopic live="+isLiveEvent);

        initRoom(event.room_id);

        // live events always update, but non-live events only update if the
        // ts is later.
        if (!isLiveEvent) {
            var eventTs = event.ts;
            var storedEvent = $rootScope.events.rooms[event.room_id][event.type];
            if (storedEvent) {
                if (storedEvent.ts > eventTs) {
                    // ignore it, we have a newer one already.
                    return;
                }
            }
        }
        $rootScope.events.rooms[event.room_id][event.type] = event;
    };

    var handleCallEvent = function(event, isLiveEvent) {
        $rootScope.$broadcast(CALL_EVENT, event, isLiveEvent);
        if (event.type == 'm.call.invite') {
            $rootScope.events.rooms[event.room_id].messages.push(event);
        }
    };
    
    return {
        ROOM_CREATE_EVENT: ROOM_CREATE_EVENT,
        MSG_EVENT: MSG_EVENT,
        MEMBER_EVENT: MEMBER_EVENT,
        PRESENCE_EVENT: PRESENCE_EVENT,
        POWERLEVEL_EVENT: POWERLEVEL_EVENT,
        CALL_EVENT: CALL_EVENT,
        NAME_EVENT: NAME_EVENT,
    
        handleEvent: function(event, isLiveEvent) {
            // Avoid duplicated events
            // Needed for rooms where initialSync has not been done. 
            // In this case, we do not know where to start pagination. So, it starts from the END
            // and we can have the same event (ex: joined, invitation) coming from the pagination
            // AND from the event stream.
            // FIXME: This workaround should be no more required when /initialSync on a particular room
            // will be available (as opposite to the global /initialSync done at startup)
            if (eventMap[event.event_id]) {
                console.log("discarding duplicate event: " + JSON.stringify(event, undefined, 4));
                return;
            }
            else {
                eventMap[event.event_id] = 1;
            }
  
            if (event.type.indexOf('m.call.') === 0) {
                handleCallEvent(event, isLiveEvent);
            }
            else {            
                switch(event.type) {
                    case "m.room.create":
                        handleRoomCreate(event, isLiveEvent);
                        break;
                    case "m.room.aliases":
                        handleRoomAliases(event, isLiveEvent);
                        break;
                    case "m.room.message":
                        handleMessage(event, isLiveEvent);
                        break;
                    case "m.room.member":
                        handleRoomMember(event, isLiveEvent);
                        break;
                    case "m.presence":
                        handlePresence(event, isLiveEvent);
                        break;
                    case 'm.room.ops_levels':
                    case 'm.room.send_event_level':
                    case 'm.room.add_state_level':
                    case 'm.room.join_rules':
                    case 'm.room.power_levels':
                        handlePowerLevels(event, isLiveEvent);
                        break;
                    case 'm.room.name':
                        handleRoomName(event, isLiveEvent);
                        break;
                    case 'm.room.topic':
                        handleRoomTopic(event, isLiveEvent);
                        break;
                    default:
                        console.log("Unable to handle event type " + event.type);
                        console.log(JSON.stringify(event, undefined, 4));
                        break;
                }
            }
        },
        
        // isLiveEvents determines whether notifications should be shown, whether
        // messages get appended to the start/end of lists, etc.
        handleEvents: function(events, isLiveEvents) {
            for (var i=0; i<events.length; i++) {
                this.handleEvent(events[i], isLiveEvents);
            }
        },

        // Handle messages from /initialSync or /messages
        handleRoomMessages: function(room_id, messages, isLiveEvents) {
            this.handleEvents(messages.chunk);

            // Store how far back we've paginated
            // This assumes the paginations requests are contiguous and in reverse chronological order
            $rootScope.events.rooms[room_id].pagination.earliest_token = messages.end;
        },

        handleInitialSyncDone: function(initialSyncData) {
            console.log("# handleInitialSyncDone");
            initialSyncDeferred.resolve(initialSyncData);
        },

        // Returns a promise that resolves when the initialSync request has been processed
        waitForInitialSyncCompletion: function() {
            return initialSyncDeferred.promise;
        },

        resetRoomMessages: function(room_id) {
            resetRoomMessages(room_id);
        }
    };
}]);
