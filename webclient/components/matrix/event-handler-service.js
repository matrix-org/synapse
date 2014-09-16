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
    var TOPIC_EVENT = "TOPIC_EVENT";
    var RESET_EVENT = "RESET_EVENT";    // eventHandlerService has been resetted

    // used for dedupping events - could be expanded in future...
    // FIXME: means that we leak memory over time (along with lots of the rest
    // of the app, given we never try to reap memory yet)
    var eventMap = {};

    $rootScope.presence = {};

    var initialSyncDeferred;

    var reset = function() {
        initialSyncDeferred = $q.defer();

        $rootScope.events = {
            rooms: {} // will contain roomId: { messages:[], members:{userid1: event} }
        };

        $rootScope.presence = {};

        eventMap = {};
    };
    reset();

    var initRoom = function(room_id) {
        if (!(room_id in $rootScope.events.rooms)) {
            console.log("Creating new handler entry for " + room_id);
            $rootScope.events.rooms[room_id] = {
                room_id: room_id,
                messages: [],
                members: {},
                // Pagination information
                pagination: {
                    earliest_token: "END"   // how far back we've paginated
                }
            };
        }
    };

    var resetRoomMessages = function(room_id) {
        if ($rootScope.events.rooms[room_id]) {
            $rootScope.events.rooms[room_id].messages = [];
        }
    };
    
    // Generic method to handle events data
    var handleRoomDateEvent = function(event, isLiveEvent, addToRoomMessages) {
        // Add topic changes as if they were a room message
        if (addToRoomMessages) {
            if (isLiveEvent) {
                $rootScope.events.rooms[event.room_id].messages.push(event);
            }
            else {
                $rootScope.events.rooms[event.room_id].messages.unshift(event);
            }
        }

        // live events always update, but non-live events only update if the
        // ts is later.
        var latestData = true;
        if (!isLiveEvent) {
            var eventTs = event.ts;
            var storedEvent = $rootScope.events.rooms[event.room_id][event.type];
            if (storedEvent) {
                if (storedEvent.ts > eventTs) {
                    // ignore it, we have a newer one already.
                    latestData = false;
                }
            }
        }
        if (latestData) {
            $rootScope.events.rooms[event.room_id][event.type] = event;         
        }
    };
    
    var handleRoomCreate = function(event, isLiveEvent) {
        // For now, we do not use the event data. Simply signal it to the app controllers
        $rootScope.$broadcast(ROOM_CREATE_EVENT, event, isLiveEvent);
    };

    var handleRoomAliases = function(event, isLiveEvent) {
        matrixService.createRoomIdToAliasMapping(event.room_id, event.content.aliases[0]);
    };

    var handleMessage = function(event, isLiveEvent) {
        if (isLiveEvent) {
            if (event.user_id === matrixService.config().user_id &&
                (event.content.msgtype === "m.text" || event.content.msgtype === "m.emote") ) {
                // Assume we've already echoed it. So, there is a fake event in the messages list of the room
                // Replace this fake event by the true one
                var index = getRoomEventIndex(event.room_id, event.event_id);
                if (index) {
                    $rootScope.events.rooms[event.room_id].messages[index] = event;
                }
                else {
                    $rootScope.events.rooms[event.room_id].messages.push(event);
                }
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
    
    var handleRoomMember = function(event, isLiveEvent, isStateEvent) {
        // if the server is stupidly re-relaying a no-op join, discard it.
        if (event.prev_content && 
            event.content.membership === "join" &&
            event.content.membership === event.prev_content.membership)
        {
            return;
        }
        
        // add membership changes as if they were a room message if something interesting changed
        // Exception: Do not do this if the event is a room state event because such events already come
        // as room messages events. Moreover, when they come as room messages events, they are relatively ordered
        // with other other room messages
        if (event.content.prev !== event.content.membership && !isStateEvent) {
            if (isLiveEvent) {
                $rootScope.events.rooms[event.room_id].messages.push(event);
            }
            else {
                $rootScope.events.rooms[event.room_id].messages.unshift(event);
            }
        }
        
        // Use data from state event or the latest data from the stream.
        // Do not care of events that come when paginating back
        if (isStateEvent || isLiveEvent) {
            $rootScope.events.rooms[event.room_id].members[event.state_key] = event;
        }
        
        $rootScope.$broadcast(MEMBER_EVENT, event, isLiveEvent, isStateEvent);
    };
    
    var handlePresence = function(event, isLiveEvent) {
        $rootScope.presence[event.content.user_id] = event;
        $rootScope.$broadcast(PRESENCE_EVENT, event, isLiveEvent);
    };
    
    var handlePowerLevels = function(event, isLiveEvent) {
        // Keep the latest data. Do not care of events that come when paginating back
        if (!$rootScope.events.rooms[event.room_id][event.type] || isLiveEvent) {
            $rootScope.events.rooms[event.room_id][event.type] = event;
            $rootScope.$broadcast(POWERLEVEL_EVENT, event, isLiveEvent);   
        }
    };

    var handleRoomName = function(event, isLiveEvent, isStateEvent) {
        console.log("handleRoomName room_id: " + event.room_id + " - isLiveEvent: " + isLiveEvent + " - name: " + event.content.name);
        handleRoomDateEvent(event, isLiveEvent, !isStateEvent);
        $rootScope.$broadcast(NAME_EVENT, event, isLiveEvent);
    };
    

    var handleRoomTopic = function(event, isLiveEvent, isStateEvent) {
        console.log("handleRoomTopic room_id: " + event.room_id + " - isLiveEvent: " + isLiveEvent + " - topic: " + event.content.topic);
        handleRoomDateEvent(event, isLiveEvent, !isStateEvent);
        $rootScope.$broadcast(TOPIC_EVENT, event, isLiveEvent);
    };

    var handleCallEvent = function(event, isLiveEvent) {
        $rootScope.$broadcast(CALL_EVENT, event, isLiveEvent);
        if (event.type === 'm.call.invite') {
            $rootScope.events.rooms[event.room_id].messages.push(event);
        }
    };
    
    /**
     * Get the index of the event in $rootScope.events.rooms[room_id].messages
     * @param {type} room_id the room id
     * @param {type} event_id the event id to look for
     * @returns {Number | undefined} the index. undefined if not found.
     */
    var getRoomEventIndex = function(room_id, event_id) {
        var index;

        var room = $rootScope.events.rooms[room_id];
        if (room) {
            // Start looking from the tail since the first goal of this function 
            // is to find a messaged among the latest ones
            for (var i = room.messages.length - 1; i > 0; i--) {
                var message = room.messages[i];
                if (event_id === message.event_id) {
                    index = i;
                    break;
                }
            }
        }
        return index;
    };
    
    return {
        ROOM_CREATE_EVENT: ROOM_CREATE_EVENT,
        MSG_EVENT: MSG_EVENT,
        MEMBER_EVENT: MEMBER_EVENT,
        PRESENCE_EVENT: PRESENCE_EVENT,
        POWERLEVEL_EVENT: POWERLEVEL_EVENT,
        CALL_EVENT: CALL_EVENT,
        NAME_EVENT: NAME_EVENT,
        TOPIC_EVENT: TOPIC_EVENT,
        RESET_EVENT: RESET_EVENT,
        
        reset: function() {
            reset();
            $rootScope.$broadcast(RESET_EVENT);
        },
    
        handleEvent: function(event, isLiveEvent, isStateEvent) {

            // FIXME: /initialSync on a particular room is not yet available
            // So initRoom on a new room is not called. Make sure the room data is initialised here
            if (event.room_id) {
                initRoom(event.room_id);
            }

            // Avoid duplicated events
            // Needed for rooms where initialSync has not been done. 
            // In this case, we do not know where to start pagination. So, it starts from the END
            // and we can have the same event (ex: joined, invitation) coming from the pagination
            // AND from the event stream.
            // FIXME: This workaround should be no more required when /initialSync on a particular room
            // will be available (as opposite to the global /initialSync done at startup)
            if (!isStateEvent) {    // Do not consider state events
                if (event.event_id && eventMap[event.event_id]) {
                    console.log("discarding duplicate event: " + JSON.stringify(event, undefined, 4));
                    return;
                }
                else {
                    eventMap[event.event_id] = 1;
                }
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
                        handleRoomMember(event, isLiveEvent, isStateEvent);
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
                        handleRoomName(event, isLiveEvent, isStateEvent);
                        break;
                    case 'm.room.topic':
                        handleRoomTopic(event, isLiveEvent, isStateEvent);
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
        handleEvents: function(events, isLiveEvents, isStateEvents) {
            for (var i=0; i<events.length; i++) {
                this.handleEvent(events[i], isLiveEvents, isStateEvents);
            }
        },

        // Handle messages from /initialSync or /messages
        handleRoomMessages: function(room_id, messages, isLiveEvents, dir) {
            initRoom(room_id);

            var events = messages.chunk;

            // Handles messages according to their time order
            if (dir && 'b' === dir) {
                // paginateBackMessages requests messages to be in reverse chronological order
                for (var i=0; i<events.length; i++) {
                    this.handleEvent(events[i], isLiveEvents, isLiveEvents);
                }
                
                // Store how far back we've paginated
                $rootScope.events.rooms[room_id].pagination.earliest_token = messages.end;
            }
            else {
                // InitialSync returns messages in chronological order
                for (var i=events.length - 1; i>=0; i--) {
                    this.handleEvent(events[i], isLiveEvents, isLiveEvents);
                }
                // Store where to start pagination
                $rootScope.events.rooms[room_id].pagination.earliest_token = messages.start;
            }
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
        },
        
        /**
         * Return the last message event of a room
         * @param {String} room_id the room id
         * @param {Boolean} filterFake true to not take into account fake messages
         * @returns {undefined | Event} the last message event if available
         */
        getLastMessage: function(room_id, filterEcho) {
            var lastMessage;

            var room = $rootScope.events.rooms[room_id];
            if (room) {
                for (var i = room.messages.length - 1; i >= 0; i--) {
                    var message = room.messages[i];

                    if (!filterEcho || undefined === message.echo_msg_state) {
                        lastMessage = message;
                        break;
                    }
                }
            }

            return lastMessage;
        },
        
        /**
         * Compute the room users number, ie the number of members who has joined the room.
         * @param {String} room_id the room id
         * @returns {undefined | Number} the room users number if available
         */
        getUsersCountInRoom: function(room_id) {
            var memberCount;

            var room = $rootScope.events.rooms[room_id];
            if (room) {
                memberCount = 0;

                for (var i in room.members) {
                    var member = room.members[i];

                    if ("join" === member.membership) {
                        memberCount = memberCount + 1;
                    }
                }
            }

            return memberCount;
        },
        
        /**
         * Get the member object of a room member
         * @param {String} room_id the room id
         * @param {String} user_id the id of the user
         * @returns {undefined | Object} the member object of this user in this room if he is part of the room
         */
        getMember: function(room_id, user_id) {
            var member;
            
            var room = $rootScope.events.rooms[room_id];
            if (room) {
                member = room.members[user_id];
            }
            return member;
        }
    };
}]);
