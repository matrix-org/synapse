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
This service serves as the entry point for all models in the app. If access to
underlying data in a room is required, then this service should be used as the
dependency.
*/
// NB: This is more explicit than linking top-level models to $rootScope
//     in that by adding this service as a dep you are clearly saying "this X
//     needs access to the underlying data store", rather than polluting the
//     $rootScope.
angular.module('modelService', [])
.factory('modelService', ['matrixService', function(matrixService) {

    // alias / id lookups
    var roomIdToAlias, aliasToRoomId;
    var setRoomIdToAliasMapping = function(roomId, alias) {
        roomIdToAlias[roomId] = alias;
        aliasToRoomId[alias] = roomId;
    };
    
    // user > room member lookups
    var userIdToRoomMember;
    
    // main store
    var rooms, users;
    
    var init = function() {
        roomIdToAlias = {};
        aliasToRoomId = {};
        userIdToRoomMember = {
            // user_id: [RoomMember, RoomMember, ...]
        };
        
        // rooms are stored here when they come in.
        rooms = {
            // roomid: <Room>
        };
        
        users = {
            // user_id: <User>
        };
        console.log("Models inited.");
    };
    
    init();
    
    /***** Room Object *****/
    var Room = function Room(room_id) {
        this.room_id = room_id;
        this.old_room_state = new RoomState();
        this.current_room_state = new RoomState();
        this.now = this.current_room_state; // makes html access shorter
        this.events = []; // events which can be displayed on the UI. TODO move?
    };
    Room.prototype = {
        addMessageEvents: function addMessageEvents(events, toFront) {
            for (var i=0; i<events.length; i++) {
                this.addMessageEvent(events[i], toFront);
            }
        },
        
        addMessageEvent: function addMessageEvent(event, toFront) {
            // every message must reference the RoomMember which made it *at
            // that time* so things like display names display correctly.
            var stateAtTheTime = toFront ? this.old_room_state : this.current_room_state;
            event.__room_member = stateAtTheTime.getStateEvent("m.room.member", event.user_id);
            if (event.type === "m.room.member" && event.content.membership === "invite") {
                // give information on both the inviter and invitee
                event.__target_room_member = stateAtTheTime.getStateEvent("m.room.member", event.state_key);
            }
            
            if (toFront) {
                this.events.unshift(event);
            }
            else {
                this.events.push(event);
            }
        },
        
        addOrReplaceMessageEvent: function addOrReplaceMessageEvent(event, toFront) {
            // Start looking from the tail since the first goal of this function 
            // is to find a message among the latest ones
            for (var i = this.events.length - 1; i >= 0; i--) {
                var storedEvent = this.events[i];
                if (storedEvent.event_id === event.event_id) {
                    // It's clobbering time!
                    this.events[i] = event;
                    return;
                }
            }
            this.addMessageEvent(event, toFront);
        },
        
        leave: function leave() {
            return matrixService.leave(this.room_id);
        }
    };
    
    /***** Room State Object *****/
    var RoomState = function RoomState() {
        // list of RoomMember
        this.members = {}; 
        // state events, the key is a compound of event type + state_key
        this.state_events = {}; 
        this.pagination_token = ""; 
    };
    RoomState.prototype = {
        // get a state event for this room from this.state_events. State events
        // are unique per type+state_key tuple, with a lot of events using 0-len
        // state keys. To make it not Really Annoying to access, this method is
        // provided which can just be given the type and it will return the 
        // 0-len event by default.
        state: function state(type, state_key) {
            if (!type) {
                return undefined; // event type MUST be specified
            }
            if (!state_key) {
                return this.state_events[type]; // treat as 0-len state key
            }
            return this.state_events[type + state_key];
        },
        
        storeStateEvent: function storeState(event) {
            var keyIndex = event.state_key === undefined ? event.type : event.type + event.state_key;
            this.state_events[keyIndex] = event;
            if (event.type === "m.room.member") {
                var userId = event.state_key;
                var rm = new RoomMember();
                rm.event = event;
                rm.user = users[userId];
                this.members[userId] = rm;
                
                // add to lookup so new m.presence events update the user
                if (!userIdToRoomMember[userId]) {
                    userIdToRoomMember[userId] = [];
                }
                userIdToRoomMember[userId].push(rm);
            }
            else if (event.type === "m.room.aliases") {
                setRoomIdToAliasMapping(event.room_id, event.content.aliases[0]);
            }
            else if (event.type === "m.room.power_levels") {
                // normalise power levels: find the max first.
                var maxPowerLevel = 0;
                for (var user_id in event.content) {
                    if (!event.content.hasOwnProperty(user_id) || user_id === "hsob_ts") continue; // XXX hsob_ts on some old rooms :(
                    maxPowerLevel = Math.max(maxPowerLevel, event.content[user_id]);
                }
                // set power level f.e room member
                var defaultPowerLevel = event.content.default === undefined ? 0 : event.content.default;
                for (var user_id in this.members) {
                    if (!this.members.hasOwnProperty(user_id)) continue;
                    var rm = this.members[user_id];
                    if (!rm) {
                        continue;
                    }
                    rm.power_level = event.content[user_id] === undefined ? defaultPowerLevel : event.content[user_id];
                    rm.power_level_norm = (rm.power_level * 100) / maxPowerLevel;
                }
            }
        },
        
        storeStateEvents: function storeState(events) {
            if (!events) {
                return;
            }
            for (var i=0; i<events.length; i++) {
                this.storeStateEvent(events[i]);
            }
        },
        
        getStateEvent: function getStateEvent(event_type, state_key) {
            return this.state_events[event_type + state_key];
        }
    };
    
    /***** Room Member Object *****/
    var RoomMember = function RoomMember() {
        this.event = {}; // the m.room.member event representing the RoomMember.
        this.power_level_norm = 0;
        this.power_level = 0;
        this.user = undefined; // the User
    };
    
    /***** User Object *****/
    var User = function User() {
        this.event = {}; // the m.presence event representing the User.
        this.last_updated = 0; // used with last_active_ago to work out last seen times
    };
    
    return {
    
        getRoom: function(roomId) {
            if(!rooms[roomId]) {
                rooms[roomId] = new Room(roomId);
            }
            return rooms[roomId];
        },
        
        getRooms: function() {
            return rooms;
        },
        
        /**
         * Get the member object of a room member
         * @param {String} room_id the room id
         * @param {String} user_id the id of the user
         * @returns {undefined | Object} the member object of this user in this room if he is part of the room
         */
        getMember: function(room_id, user_id) {
            var room = this.getRoom(room_id);
            return room.current_room_state.members[user_id];
        },
        
        createRoomIdToAliasMapping: function(roomId, alias) {
            setRoomIdToAliasMapping(roomId, alias);
        },
        
        getRoomIdToAliasMapping: function(roomId) {
            var alias = roomIdToAlias[roomId];
            //console.log("looking for alias for " + roomId + "; found: " + alias);
            return alias;
        },

        getAliasToRoomIdMapping: function(alias) {
            var roomId = aliasToRoomId[alias];
            //console.log("looking for roomId for " + alias + "; found: " + roomId);
            return roomId;
        },
        
        getUser: function(user_id) {
            return users[user_id];
        },
        
        setUser: function(event) {
            var usr = new User();
            usr.event = event;
            
            // migrate old data but clobber matching keys
            if (users[event.content.user_id] && users[event.content.user_id].event) {
                angular.extend(users[event.content.user_id].event, event);
                usr = users[event.content.user_id];
            }
            else {
                users[event.content.user_id] = usr;
            }
            
            usr.last_updated = new Date().getTime();
            
            // update room members
            var roomMembers = userIdToRoomMember[event.content.user_id];
            if (roomMembers) {
                for (var i=0; i<roomMembers.length; i++) {
                    var rm = roomMembers[i];
                    rm.user = usr;
                }
            }
        },
        
        /**
         * Return the power level of an user in a particular room
         * @param {String} room_id the room id
         * @param {String} user_id the user id
         * @returns {Number}
         */
        getUserPowerLevel: function(room_id, user_id) {
            var powerLevel = 0;
            var room = this.getRoom(room_id).current_room_state;
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
         * Compute the room users number, ie the number of members who has joined the room.
         * @param {String} room_id the room id
         * @returns {undefined | Number} the room users number if available
         */
        getUserCountInRoom: function(room_id) {
            var memberCount;

            var room = this.getRoom(room_id);
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
         * Return the last message event of a room
         * @param {String} room_id the room id
         * @param {Boolean} filterFake true to not take into account fake messages
         * @returns {undefined | Event} the last message event if available
         */
        getLastMessage: function(room_id, filterEcho) {
            var lastMessage;

            var events = this.getRoom(room_id).events;
            for (var i = events.length - 1; i >= 0; i--) {
                var message = events[i];

                // TODO: define a better marker than echo_msg_state
                if (!filterEcho || undefined === message.echo_msg_state) {
                    lastMessage = message;
                    break;
                }
            }

            return lastMessage;
        },
        
        clearRooms: function() {
            init();
        }
    
    };
}]);
