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

var matrixWebClient = angular.module('matrixWebClient', [
    'ngRoute',
    'MatrixWebClientController',
    'LoginController',
    'RoomController',
    'RoomsController',
    'matrixService',
    'eventStreamService',
    'eventHandlerService',
    'infinite-scroll'
]);

matrixWebClient.config(['$routeProvider', '$provide', '$httpProvider',
    function($routeProvider, $provide, $httpProvider) {
        $routeProvider.
            when('/login', {
                templateUrl: 'login/login.html',
                controller: 'LoginController'
            }).
            when('/room/:room_id', {
                templateUrl: 'room/room.html',
                controller: 'RoomController'
            }).
            when('/rooms', {
                templateUrl: 'rooms/rooms.html',
                controller: 'RoomsController'
            }).
            otherwise({
                redirectTo: '/rooms'
            });
            
        $provide.factory('AccessTokenInterceptor', ['$q', '$rootScope', 
            function ($q, $rootScope) {
            return {
                responseError: function(rejection) {
                    if (rejection.status === 403 && "data" in rejection && 
                            "errcode" in rejection.data && 
                            rejection.data.errcode === "M_UNKNOWN_TOKEN") {
                        console.log("Got a 403 with an unknown token. Logging out.")
                        $rootScope.$broadcast("M_UNKNOWN_TOKEN");
                    }
                    return $q.reject(rejection);
                }
            };
        }]);
        $httpProvider.interceptors.push('AccessTokenInterceptor');
    }]);

matrixWebClient.run(['$location', 'matrixService', 'eventStreamService', function($location, matrixService, eventStreamService) {
    // If we have no persistent login information, go to the login page
    var config = matrixService.config();
    if (!config || !config.access_token) {
        eventStreamService.stop();
        $location.path("login");
    }
    else {
        eventStreamService.resume();
    }
}]);

matrixWebClient
    .directive('ngEnter', function () {
        return function (scope, element, attrs) {
            element.bind("keydown keypress", function (event) {
                if(event.which === 13) {
                    scope.$apply(function () {
                        scope.$eval(attrs.ngEnter);
                    });
                    event.preventDefault();
                }
            });
        };
    })
    .directive('ngFocus', ['$timeout', function($timeout) {
        return {
            link: function(scope, element, attr) {
                $timeout(function() { element[0].focus() }, 0);
            }
        };
    }])
    .filter('to_trusted', ['$sce', function($sce){
        return function(text) {
            return $sce.trustAsHtml(text);
        };
    }]);
