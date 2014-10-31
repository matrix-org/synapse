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
.factory('eventHandlerService', ['matrixService', '$rootScope', '$q', '$timeout', 'mPresence', 'notificationService', 'modelService',
function(matrixService, $rootScope, $q, $timeout, mPresence, notificationService, modelService) {
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

    var initRoom = function(room_id, room) {
        if (!(room_id in $rootScope.events.rooms)) {
            console.log("Creating new rooms entry for " + room_id);
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

        if (room) { // we got an existing room object from initialsync, seemingly.
            // Report all other metadata of the room object (membership, inviter, visibility, ...)
            for (var field in room) {
                if (!room.hasOwnProperty(field)) continue;

                if (-1 === ["room_id", "messages", "state"].indexOf(field)) { // why indexOf - why not ===? --Matthew
                    $rootScope.events.rooms[room_id][field] = room[field];
                }
            }
            $rootScope.events.rooms[room_id].membership = room.membership;
        }
        
        // =========================================
        var __room = modelService.getRoom(room_id);
        if (room) { // /initialSync data
            __room.current_room_state.storeStateEvents(room.state);
            __room.current_room_state.pagination_token = room.messages.end;
            
            __room.old_room_state.storeStateEvents(room.state);
            __room.old_room_state.pagination_token = room.messages.start;
            
            $rootScope["debug_"+room_id] = __room;
        }
    };

    var resetRoomMessages = function(room_id) {
        if ($rootScope.events.rooms[room_id]) {
            $rootScope.events.rooms[room_id].messages = [];
        }
    };
    
    // Generic method to handle events data
    var handleRoomDateEvent = function(event, isLiveEvent, addToRoomMessages) {
        var __room = modelService.getRoom(event.room_id);
        if (addToRoomMessages) {
            __room.addMessageEvent(event, !isLiveEvent);
        }
        if (isLiveEvent) {
            __room.current_room_state.storeStateEvent(event);
        }
        else {
            var eventTs = event.origin_server_ts;
            var storedEvent = __room.current_room_state.getStateEvent(event.type, event.state_key);
            if (storedEvent) {
                if (storedEvent.origin_server_ts < eventTs) {
                    // the incoming event is newer, use it.
                    __room.current_room_state.storeStateEvent(event);
                }
            }
        }
    
        // =====================================
    
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
            var eventTs = event.origin_server_ts;
            var storedEvent = $rootScope.events.rooms[event.room_id][event.type];
            if (storedEvent) {
                if (storedEvent.origin_server_ts > eventTs) {
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
    
    var displayNotification = function(event) {
        if (window.Notification && event.user_id != matrixService.config().user_id) {
            var shouldBing = notificationService.containsBingWord(
                matrixService.config().user_id,
                matrixService.config().display_name,
                matrixService.config().bingWords,
                event.content.body
            );

            // Ideally we would notify only when the window is hidden (i.e. document.hidden = true).
            //
            // However, Chrome on Linux and OSX currently returns document.hidden = false unless the window is
            // explicitly showing a different tab.  So we need another metric to determine hiddenness - we
            // simply use idle time.  If the user has been idle enough that their presence goes to idle, then
            // we also display notifs when things happen.
            //
            // This is far far better than notifying whenever anything happens anyway, otherwise you get spammed
            // to death with notifications when the window is in the foreground, which is horrible UX (especially
            // if you have not defined any bingers and so get notified for everything).
            var isIdle = (document.hidden || matrixService.presence.unavailable === mPresence.getState());
            
            // We need a way to let people get notifications for everything, if they so desire.  The way to do this
            // is to specify zero bingwords.
            var bingWords = matrixService.config().bingWords;
            if (bingWords === undefined || bingWords.length === 0) {
                shouldBing = true;
            }
            
            if (shouldBing && isIdle) {
                console.log("Displaying notification for "+JSON.stringify(event));
                var member = getMember(event.room_id, event.user_id);
                var displayname = getUserDisplayName(event.room_id, event.user_id);

                var message = event.content.body;
                if (event.content.msgtype === "m.emote") {
                    message = "* " + displayname + " " + message;
                }
                else if (event.content.msgtype === "m.image") {
                    message = displayname + " sent an image.";
                }

                var roomTitle = matrixService.getRoomIdToAliasMapping(event.room_id);
                var theRoom = $rootScope.events.rooms[event.room_id];
                if (!roomTitle && theRoom && theRoom["m.room.name"] && theRoom["m.room.name"].content) {
                    roomTitle = theRoom["m.room.name"].content.name;
                }

                if (!roomTitle) {
                    roomTitle = event.room_id;
                }
                
                notificationService.showNotification(
                    displayname + " (" + roomTitle + ")",
                    message,
                    member ? member.avatar_url : undefined,
                    function() {
                        console.log("notification.onclick() room=" + event.room_id);
                        $rootScope.goToPage('room/' + event.room_id); 
                    }
                );
            }
        }
    };

    var handleMessage = function(event, isLiveEvent) {
        // Check for empty event content
        var hasContent = false;
        for (var prop in event.content) {
            hasContent = true;
            break;
        }
        if (!hasContent) {
            // empty json object is a redacted event, so ignore.
            return;
        }
        
        // =======================
        
        var __room = modelService.getRoom(event.room_id);
        
        if (event.user_id !== matrixService.config().user_id) {
            __room.addMessageEvent(event, !isLiveEvent);
        }
        else {
            // we may have locally echoed this, so we should replace the event
            // instead of just adding.
            __room.addOrReplaceMessageEvent(event, !isLiveEvent);
        }
        
        // =======================

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
                displayNotification(event);
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
        var __room = modelService.getRoom(event.room_id);
        
        
        // add membership changes as if they were a room message if something interesting changed
        // Exception: Do not do this if the event is a room state event because such events already come
        // as room messages events. Moreover, when they come as room messages events, they are relatively ordered
        // with other other room messages
        if (!isStateEvent) {
            // could be a membership change, display name change, etc.
            // Find out which one.
            var memberChanges = undefined;
            if ((event.prev_content === undefined && event.content.membership) || (event.prev_content && (event.prev_content.membership !== event.content.membership))) {
                memberChanges = "membership";
            }
            else if (event.prev_content && (event.prev_content.displayname !== event.content.displayname)) {
                memberChanges = "displayname";
            }

            // mark the key which changed
            event.changedKey = memberChanges;

            // If there was a change we want to display, dump it in the message
            // list.
            if (memberChanges) {
                if (isLiveEvent) {
                    $rootScope.events.rooms[event.room_id].messages.push(event);
                }
                else {
                    $rootScope.events.rooms[event.room_id].messages.unshift(event);
                }
                // ============
                
                __room.addMessageEvent(event, !isLiveEvent);
            }
        }
        
        // Use data from state event or the latest data from the stream.
        // Do not care of events that come when paginating back
        if (isStateEvent || isLiveEvent) {
            $rootScope.events.rooms[event.room_id].members[event.state_key] = event;
            __room.current_room_state.members[event.state_key] = event;
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

    var handleRedaction = function(event, isLiveEvent) {
        if (!isLiveEvent) {
            // we have nothing to remove, so just ignore it.
            console.log("Received redacted event: "+JSON.stringify(event));
            return;
        }

        // we need to remove something possibly: do we know the redacted
        // event ID?
        if (eventMap[event.redacts]) {
            // remove event from list of messages in this room.
            var eventList = $rootScope.events.rooms[event.room_id].messages;
            for (var i=0; i<eventList.length; i++) {
                if (eventList[i].event_id === event.redacts) {
                    console.log("Removing event " + event.redacts);
                    eventList.splice(i, 1);
                    break;
                }
            }

            // broadcast the redaction so controllers can nuke this
            console.log("Redacted an event.");
        }
    }
    
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
    
    /**
     * Get the member object of a room member
     * @param {String} room_id the room id
     * @param {String} user_id the id of the user
     * @returns {undefined | Object} the member object of this user in this room if he is part of the room
     */
    var getMember = function(room_id, user_id) {
        var member;

        var room = $rootScope.events.rooms[room_id];
        if (room) {
            member = room.members[user_id];
        }
        return member;
    };

    /**
     * Return the display name of an user acccording to data already downloaded
     * @param {String} room_id the room id
     * @param {String} user_id the id of the user
     * @returns {String} the user displayname or user_id if not available
     */
    var getUserDisplayName = function(room_id, user_id) {
        var displayName;

        // Get the user display name from the member list of the room
        var member = getMember(room_id, user_id);
        if (member && member.content.displayname) { // Do not consider null displayname
            displayName = member.content.displayname;

            // Disambiguate users who have the same displayname in the room
            if (user_id !== matrixService.config().user_id) {
                var room = $rootScope.events.rooms[room_id];

                for (var member_id in room.members) {
                    if (room.members.hasOwnProperty(member_id) && member_id !== user_id) {
                        var member2 = room.members[member_id];
                        if (member2.content.displayname && member2.content.displayname === displayName) {
                            displayName = displayName + " (" + user_id + ")";
                            break;
                        }
                    }
                }
            }
        }

        // The user may not have joined the room yet. So try to resolve display name from presence data
        // Note: This data may not be available
        if (undefined === displayName && user_id in $rootScope.presence) {
            displayName = $rootScope.presence[user_id].content.displayname;
        }

        if (undefined === displayName) {
            // By default, use the user ID
            displayName = user_id;
        }
        return displayName;
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
        
        initRoom: function(room) {
            initRoom(room.room_id, room);
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
                    case 'm.room.redaction':
                        handleRedaction(event, isLiveEvent);
                        break;
                    default:
                        // if it is a state event, then just add it in so it
                        // displays on the Room Info screen.
                        if (typeof(event.state_key) === "string") { // incls. 0-len strings
                            if (event.room_id) {
                                handleRoomDateEvent(event, isLiveEvent, false);
                            }
                        }
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
                
                var __room = modelService.getRoom(room_id);
                __room.old_room_state.pagination_token = messages.end;
                
            }
            else {
                // InitialSync returns messages in chronological order
                for (var i=events.length - 1; i>=0; i--) {
                    this.handleEvent(events[i], isLiveEvents, isLiveEvents);
                }
                // Store where to start pagination
                $rootScope.events.rooms[room_id].pagination.earliest_token = messages.start;
                
                var __room = modelService.getRoom(room_id);
                __room.old_room_state.pagination_token = messages.start;
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
                    if (!room.members.hasOwnProperty(i)) continue;

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
            return getMember(room_id, user_id);
        },
        
        /**
         * Return the display name of an user acccording to data already downloaded
         * @param {String} room_id the room id
         * @param {String} user_id the id of the user
         * @returns {String} the user displayname or user_id if not available
         */
        getUserDisplayName: function(room_id, user_id) {
            return getUserDisplayName(room_id, user_id);
        },

        setRoomVisibility: function(room_id, visible) {
            if (!visible) {
                return;
            }
            initRoom(room_id);
            
            var room = $rootScope.events.rooms[room_id];
            if (room) {
                room.visibility = visible;
            }
        }
    };
}]);
