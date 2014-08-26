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
This service handles what should happen when you get an event. This service does
not care where the event came from, it only needs enough context to be able to 
process them. Events may be coming from the event stream, the REST API (via 
direct GETs or via a pagination stream API), etc.

Typically, this service will store events or broadcast them to any listeners
(e.g. controllers) via $broadcast. Alternatively, it may update the $rootScope
if typically all the $on method would do is update its own $scope.
*/
angular.module('eventHandlerService', [])
.factory('eventHandlerService', ['matrixService', '$rootScope', function(matrixService, $rootScope) {
    var MSG_EVENT = "MSG_EVENT";
    var MEMBER_EVENT = "MEMBER_EVENT";
    var PRESENCE_EVENT = "PRESENCE_EVENT";
    
    $rootScope.events = {
        rooms: {}, // will contain roomId: { messages:[], members:{userid1: event} }
    };

    $rootScope.presence = {};
    
    var initRoom = function(room_id) {
        if (!(room_id in $rootScope.events.rooms)) {
            console.log("Creating new handler entry for " + room_id);
            $rootScope.events.rooms[room_id] = {};
            $rootScope.events.rooms[room_id].messages = [];
            $rootScope.events.rooms[room_id].members = {};
        }
    }

    var reInitRoom = function(room_id) {
        $rootScope.events.rooms[room_id] = {};
        $rootScope.events.rooms[room_id].messages = [];
        $rootScope.events.rooms[room_id].members = {};
    }
    
    var handleMessage = function(event, isLiveEvent) {
        initRoom(event.room_id);
        
        if (isLiveEvent) {
            $rootScope.events.rooms[event.room_id].messages.push(event);
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
        
        // add membership changes as if they were a room message if something interesting changed
        if (event.content.prev !== event.content.membership) {
            if (isLiveEvent) {
                $rootScope.events.rooms[event.room_id].messages.push(event);
            }
            else {
                $rootScope.events.rooms[event.room_id].messages.unshift(event);
            }
        }
        
        $rootScope.events.rooms[event.room_id].members[event.user_id] = event;
        $rootScope.$broadcast(MEMBER_EVENT, event, isLiveEvent);
    };
    
    var handlePresence = function(event, isLiveEvent) {
        $rootScope.presence[event.content.user_id] = event;
        $rootScope.$broadcast(PRESENCE_EVENT, event, isLiveEvent);
    };
    
    
    return {
        MSG_EVENT: MSG_EVENT,
        MEMBER_EVENT: MEMBER_EVENT,
        PRESENCE_EVENT: PRESENCE_EVENT,
        
    
        handleEvent: function(event, isLiveEvent) {
            switch(event.type) {
                case "m.room.message":
                    handleMessage(event, isLiveEvent);
                    break;
                case "m.room.member":
                    handleRoomMember(event, isLiveEvent);
                    break;
                case "m.presence":
                    handlePresence(event, isLiveEvent);
                    break;
                default:
                    console.log("Unable to handle event type " + event.type);
                    break;
            }
        },
        
        // isLiveEvents determines whether notifications should be shown, whether
        // messages get appended to the start/end of lists, etc.
        handleEvents: function(events, isLiveEvents) {
            for (var i=0; i<events.length; i++) {
                this.handleEvent(events[i], isLiveEvents);
            }
        },

        reInitRoom: function(room_id) {
            reInitRoom(room_id);
        },
    };
}]);
