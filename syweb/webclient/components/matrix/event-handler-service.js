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

Typically, this service will store events and broadcast them to any listeners
(e.g. controllers) via $broadcast. 
*/
angular.module('eventHandlerService', [])
.factory('eventHandlerService', ['matrixService', '$rootScope', '$q', '$timeout', '$filter', 'mPresence', 'notificationService', 'modelService',
function(matrixService, $rootScope, $q, $timeout, $filter, mPresence, notificationService, modelService) {
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

    var initialSyncDeferred;

    var reset = function() {
        initialSyncDeferred = $q.defer();

        eventMap = {};
    };
    reset();

    var resetRoomMessages = function(room_id) {
        var room = modelService.getRoom(room_id);
        room.events = [];
    };
    
    // Generic method to handle events data
    var handleRoomStateEvent = function(event, isLiveEvent, addToRoomMessages) {
        var room = modelService.getRoom(event.room_id);
        if (addToRoomMessages) {
            // some state events are displayed as messages, so add them.
            room.addMessageEvent(event, !isLiveEvent);
        }
        
        if (isLiveEvent) {
            // update the current room state with the latest state
            room.current_room_state.storeStateEvent(event);
        }
        else {
            var eventTs = event.origin_server_ts;
            var storedEvent = room.current_room_state.getStateEvent(event.type, event.state_key);
            if (storedEvent) {
                if (storedEvent.origin_server_ts < eventTs) {
                    // the incoming event is newer, use it.
                    room.current_room_state.storeStateEvent(event);
                }
            }
        }
        // TODO: handle old_room_state
    };
    
    var handleRoomCreate = function(event, isLiveEvent) {
        $rootScope.$broadcast(ROOM_CREATE_EVENT, event, isLiveEvent);
    };

    var handleRoomAliases = function(event, isLiveEvent) {
        modelService.createRoomIdToAliasMapping(event.room_id, event.content.aliases[0]);
    };
    
    var containsBingWord = function(event) {
        if (!event.content || !event.content.body) {
            return false;
        }
    
        return notificationService.containsBingWord(
            matrixService.config().user_id,
            matrixService.config().display_name,
            matrixService.config().bingWords,
            event.content.body
        );
    };
    
    var displayNotification = function(event) {
        if (window.Notification && event.user_id != matrixService.config().user_id) {
            var member = modelService.getMember(event.room_id, event.user_id);
            var displayname = getUserDisplayName(event.room_id, event.user_id);
            var message;
            var shouldBing = false;
            
            if (event.type === "m.room.message") {
                shouldBing = containsBingWord(event);
                message = event.content.body;
                if (event.content.msgtype === "m.emote") {
                    message = "* " + displayname + " " + message;
                }
                else if (event.content.msgtype === "m.image") {
                    message = displayname + " sent an image.";
                }
            }
            else if (event.type == "m.room.member") {
                // Notify when another user joins only
                if (event.state_key !== matrixService.config().user_id  && "join" === event.content.membership) {
                    member = modelService.getMember(event.room_id, event.state_key);
                    displayname = getUserDisplayName(event.room_id, event.state_key);
                    message = displayname + " joined";
                    shouldBing = true;
                }
                else {
                    return;
                }
            }

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

                var roomTitle = $filter("mRoomName")(event.room_id);
                
                notificationService.showNotification(
                    displayname + " (" + roomTitle + ")",
                    message,
                    member ? member.event.content.avatar_url : undefined,
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
        
        var room = modelService.getRoom(event.room_id);
        
        if (event.user_id !== matrixService.config().user_id) {
            room.addMessageEvent(event, !isLiveEvent);
            displayNotification(event);
        }
        else {
            // we may have locally echoed this, so we should replace the event
            // instead of just adding.
            room.addOrReplaceMessageEvent(event, !isLiveEvent);
        }
        
        // TODO send delivery receipt if isLiveEvent
        
        $rootScope.$broadcast(MSG_EVENT, event, isLiveEvent);
    };
    
    var handleRoomMember = function(event, isLiveEvent, isStateEvent) {
        var room = modelService.getRoom(event.room_id);
        
        // did something change?
        var memberChanges = undefined;
        if (!isStateEvent) {
            // could be a membership change, display name change, etc.
            // Find out which one.
            if ((event.prev_content === undefined && event.content.membership) || (event.prev_content && (event.prev_content.membership !== event.content.membership))) {
                memberChanges = "membership";
            }
            else if (event.prev_content && (event.prev_content.displayname !== event.content.displayname)) {
                memberChanges = "displayname";
            }
            // mark the key which changed
            event.changedKey = memberChanges;
        }
        
        
        // modify state before adding the message so it points to the right thing.
        // The events are copied to avoid referencing the same event when adding
        // the message (circular json structures)
        if (isStateEvent || isLiveEvent) {
            var newEvent = angular.copy(event);
            newEvent.cnt = event.content;
            room.current_room_state.storeStateEvent(newEvent);
        }
        else if (!isLiveEvent) {
            // mutate the old room state
            var oldEvent = angular.copy(event);
            oldEvent.cnt = event.content;
            if (event.prev_content) {
                // the m.room.member event we are handling is the NEW event. When
                // we keep going back in time, we want the PREVIOUS value for displaying
                // names/etc, hence the clobber here.
                oldEvent.cnt = event.prev_content;
            }
            
            if (event.changedKey === "membership" && event.content.membership === "join") {
                // join has a prev_content but it doesn't contain all the info unlike the join, so use that.
                oldEvent.cnt = event.content;
            }
            
            room.old_room_state.storeStateEvent(oldEvent);
        }
        
        // If there was a change we want to display, dump it in the message
        // list. This has to be done after room state is updated.
        if (memberChanges) {
            room.addMessageEvent(event, !isLiveEvent);
            
            if (memberChanges === "membership" && isLiveEvent) {
                displayNotification(event);
            }
        }
        
        
        
        $rootScope.$broadcast(MEMBER_EVENT, event, isLiveEvent, isStateEvent);
    };
    
    var handlePresence = function(event, isLiveEvent) {
        modelService.setUser(event);
        $rootScope.$broadcast(PRESENCE_EVENT, event, isLiveEvent);
    };
    
    var handlePowerLevels = function(event, isLiveEvent) {
        handleRoomStateEvent(event, isLiveEvent);
        $rootScope.$broadcast(POWERLEVEL_EVENT, event, isLiveEvent);   
    };

    var handleRoomName = function(event, isLiveEvent, isStateEvent) {
        console.log("handleRoomName room_id: " + event.room_id + " - isLiveEvent: " + isLiveEvent + " - name: " + event.content.name);
        handleRoomStateEvent(event, isLiveEvent, !isStateEvent);
        $rootScope.$broadcast(NAME_EVENT, event, isLiveEvent);
    };
    

    var handleRoomTopic = function(event, isLiveEvent, isStateEvent) {
        console.log("handleRoomTopic room_id: " + event.room_id + " - isLiveEvent: " + isLiveEvent + " - topic: " + event.content.topic);
        handleRoomStateEvent(event, isLiveEvent, !isStateEvent);
        $rootScope.$broadcast(TOPIC_EVENT, event, isLiveEvent);
    };

    var handleCallEvent = function(event, isLiveEvent) {
        $rootScope.$broadcast(CALL_EVENT, event, isLiveEvent);
        if (event.type === 'm.call.invite') {
            var room = modelService.getRoom(event.room_id);
            room.addMessageEvent(event, !isLiveEvent);
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
            var room = modelService.getRoom(event.room_id);
            // remove event from list of messages in this room.
            var eventList = room.events;
            for (var i=0; i<eventList.length; i++) {
                if (eventList[i].event_id === event.redacts) {
                    console.log("Removing event " + event.redacts);
                    eventList.splice(i, 1);
                    break;
                }
            }

            console.log("Redacted an event.");
        }
    }

    /**
     * Return the display name of an user acccording to data already downloaded
     * @param {String} room_id the room id
     * @param {String} user_id the id of the user
     * @param {boolean} wrap whether to insert whitespace into the userid (if displayname not available) to help it wrap
     * @returns {String} the user displayname or user_id if not available
     */
    var getUserDisplayName = function(room_id, user_id, wrap) {
        var displayName;

        // Get the user display name from the member list of the room
        var member = modelService.getMember(room_id, user_id);
        if (member) {
            member = member.event;
        }
        if (member && member.content.displayname) { // Do not consider null displayname
            displayName = member.content.displayname;

            // Disambiguate users who have the same displayname in the room
            if (user_id !== matrixService.config().user_id) {
                var room = modelService.getRoom(room_id);

                for (var member_id in room.current_room_state.members) {
                    if (room.current_room_state.members.hasOwnProperty(member_id) && member_id !== user_id) {
                        var member2 = room.current_room_state.members[member_id].event;
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
        if (undefined === displayName) {
            var usr = modelService.getUser(user_id);
            if (usr) {
                displayName = usr.event.content.displayname;
            }
        }

        if (undefined === displayName) {
            // By default, use the user ID
            if (wrap && user_id.indexOf(':') >= 0) {
                displayName = user_id.substr(0, user_id.indexOf(':')) + " " + user_id.substr(user_id.indexOf(':'));
            }
            else {
                displayName = user_id;
            }
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
    
        handleEvent: function(event, isLiveEvent, isStateEvent) {

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
                                handleRoomStateEvent(event, isLiveEvent, false);
                            }
                        }
                        console.log("Unable to handle event type " + event.type);
                        // console.log(JSON.stringify(event, undefined, 4));
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
            var events = messages.chunk;

            // Handles messages according to their time order
            if (dir && 'b' === dir) {
                // paginateBackMessages requests messages to be in reverse chronological order
                for (var i=0; i<events.length; i++) {
                    this.handleEvent(events[i], isLiveEvents, isLiveEvents);
                }
                
                // Store how far back we've paginated
                var room = modelService.getRoom(room_id);
                room.old_room_state.pagination_token = messages.end;

            }
            else {
                // InitialSync returns messages in chronological order, so invert
                // it to get most recent > oldest
                for (var i=events.length - 1; i>=0; i--) {
                    this.handleEvent(events[i], isLiveEvents, isLiveEvents);
                }
                // Store where to start pagination
                var room = modelService.getRoom(room_id);
                room.old_room_state.pagination_token = messages.start;
            }
        },

        handleInitialSyncDone: function(response) {
            console.log("# handleInitialSyncDone");

            var rooms = response.data.rooms;
            for (var i = 0; i < rooms.length; ++i) {
                var room = rooms[i];
                
                // FIXME: This is ming: the HS should be sending down the m.room.member
                // event for the invite in .state but it isn't, so fudge it for now.
                if (room.inviter && room.membership === "invite") {
                    var me = matrixService.config().user_id;
                    var fakeEvent = {
                        event_id: "__FAKE__" + room.room_id,
                        user_id: room.inviter,
                        origin_server_ts: 0,
                        room_id: room.room_id,
                        state_key: me,
                        type: "m.room.member",
                        content: {
                            membership: "invite"
                        }
                    };
                    if (!room.state) {
                        room.state = [];
                    }
                    room.state.push(fakeEvent);
                    console.log("RECV /initialSync invite >> "+room.room_id);
                }
                
                var newRoom = modelService.getRoom(room.room_id);
                newRoom.current_room_state.storeStateEvents(room.state);
                newRoom.old_room_state.storeStateEvents(room.state);

                // this should be done AFTER storing state events since these
                // messages may make the old_room_state diverge.
                if ("messages" in room) {
                    this.handleRoomMessages(room.room_id, room.messages, false);
                    newRoom.current_room_state.pagination_token = room.messages.end;
                    newRoom.old_room_state.pagination_token = room.messages.start;
                }
            }
            var presence = response.data.presence;
            this.handleEvents(presence, false);

            initialSyncDeferred.resolve(response);
        },

        // Returns a promise that resolves when the initialSync request has been processed
        waitForInitialSyncCompletion: function() {
            return initialSyncDeferred.promise;
        },

        resetRoomMessages: function(room_id) {
            resetRoomMessages(room_id);
        },
        
        eventContainsBingWord: function(event) {
            return containsBingWord(event);
        },
        
        /**
         * Return the last message event of a room
         * @param {String} room_id the room id
         * @param {Boolean} filterFake true to not take into account fake messages
         * @returns {undefined | Event} the last message event if available
         */
        getLastMessage: function(room_id, filterEcho) {
            var lastMessage;

            var events = modelService.getRoom(room_id).events;
            for (var i = events.length - 1; i >= 0; i--) {
                var message = events[i];

                if (!filterEcho || undefined === message.echo_msg_state) {
                    lastMessage = message;
                    break;
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

            var room = modelService.getRoom(room_id);
            memberCount = 0;
            for (var i in room.current_room_state.members) {
                if (!room.current_room_state.members.hasOwnProperty(i)) continue;

                var member = room.current_room_state.members[i].event;

                if ("join" === member.content.membership) {
                    memberCount = memberCount + 1;
                }
            }

            return memberCount;
        },
        
        /**
         * Return the power level of an user in a particular room
         * @param {String} room_id the room id
         * @param {String} user_id the user id
         * @returns {Number} a value between 0 and 10
         */
        getUserPowerLevel: function(room_id, user_id) {
            var powerLevel = 0;
            var room = modelService.getRoom(room_id).current_room_state;
            if (room.state("m.room.power_levels")) {
                if (user_id in room.state("m.room.power_levels").content) {
                    powerLevel = room.state("m.room.power_levels").content[user_id];
                }
                else {
                    // Use the room default user power
                    powerLevel = room.state("m.room.power_levels").content["default"];
                }
            }
            return powerLevel;
        },
        
        /**
         * Return the display name of an user acccording to data already downloaded
         * @param {String} room_id the room id
         * @param {String} user_id the id of the user
         * @param {boolean} wrap whether to insert whitespace into the userid (if displayname not available) to help it wrap
         * @returns {String} the user displayname or user_id if not available
         */
        getUserDisplayName: function(room_id, user_id, wrap) {
            return getUserDisplayName(room_id, user_id, wrap);
        }
    };
}]);
