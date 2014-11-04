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
.controller('RecentsController', ['$rootScope', '$scope', 'eventHandlerService', 'modelService', 
                               function($rootScope, $scope, eventHandlerService, modelService) {

    // Expose the service to the view
    $scope.eventHandlerService = eventHandlerService;
    
    // retrieve all rooms and expose them
    $scope.rooms = modelService.getRooms();

    // $rootScope of the parent where the recents component is included can override this value
    // in order to highlight a specific room in the list
    $rootScope.recentsSelectedRoomID;

}]);

