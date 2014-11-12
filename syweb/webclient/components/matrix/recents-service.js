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
This service manages shared state between *instances* of recent lists. The
recents controller will hook into this central service to get things like:
- which rooms should be highlighted
- which rooms have been binged
- which room is currently selected
- etc.
This is preferable to polluting the $rootScope with recents specific info, and
makes the dependency on this shared state *explicit*.
*/
angular.module('recentsService', [])
.factory('recentsService', ['$rootScope', function($rootScope) {
    // notify listeners when variables in the service are updated. We need to do
    // this since we do not tie them to any scope.
    var BROADCAST_SELECTED_ROOM_ID = "recentsService:BROADCAST_SELECTED_ROOM_ID";
    var selectedRoomId = undefined;
    
    
    return {
        BROADCAST_SELECTED_ROOM_ID: BROADCAST_SELECTED_ROOM_ID,
    
        getSelectedRoomId: function() {
            return selectedRoomId;
        },
        
        setSelectedRoomId: function(room_id) {
            selectedRoomId = room_id;
            $rootScope.$broadcast(BROADCAST_SELECTED_ROOM_ID, room_id);
        }
    
    };

}]);
