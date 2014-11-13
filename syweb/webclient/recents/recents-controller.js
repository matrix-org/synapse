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

angular.module('RecentsController', ['matrixService', 'matrixFilter'])
.controller('RecentsController', ['$rootScope', '$scope', 'eventHandlerService', 'modelService', 'recentsService',
                               function($rootScope, $scope, eventHandlerService, modelService, recentsService) {

    // Expose the service to the view
    $scope.eventHandlerService = eventHandlerService;
    
    // retrieve all rooms and expose them
    $scope.rooms = modelService.getRooms();
    
    // track the selected room ID: the html will use this
    $scope.recentsSelectedRoomID = recentsService.getSelectedRoomId();
    $scope.$on(recentsService.BROADCAST_SELECTED_ROOM_ID, function(ngEvent, room_id) {
        $scope.recentsSelectedRoomID = room_id;
    });
    
    // track the list of unread messages: the html will use this
    $scope.unreadMessages = recentsService.getUnreadMessages();
    $scope.$on(recentsService.BROADCAST_UNREAD_MESSAGES, function(ngEvent, room_id, unreadCount) {
        $scope.unreadMessages = recentsService.getUnreadMessages();
    });
    
    // track the list of unread BING messages: the html will use this
    $scope.unreadBings = recentsService.getUnreadBingMessages();
    $scope.$on(recentsService.BROADCAST_UNREAD_BING_MESSAGES, function(ngEvent, room_id, event) {
        $scope.unreadBings = recentsService.getUnreadBingMessages();
    });
    
    $scope.selectRoom = function(room) {
        recentsService.markAsRead(room.room_id);
        $rootScope.goToPage('room/' + (room.room_alias ? room.room_alias : room.room_id) );
    };

}]);

