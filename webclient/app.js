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
    'matrixService'
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
            
        $provide.factory('AccessTokenInterceptor', function ($q) {
            return {
                responseError: function(rejection) {
                    console.log("Rejection: " + JSON.stringify(rejection));
                    if (rejection.status === 403 && "data" in rejection && 
                            "errcode" in rejection.data && 
                            rejection.data.errcode === "M_UNKNOWN_TOKEN") {
                        console.log("TODO: Got a 403 with an unknown token. Logging out.")
                        // TODO logout
                    }
                    return $q.reject(rejection);
                }
            };
        });
        $httpProvider.interceptors.push('AccessTokenInterceptor');
    }]);

matrixWebClient.run(['$location', 'matrixService' , function($location, matrixService) {
    // If we have no persistent login information, go to the login page
    var config = matrixService.config();
    if (!config || !config.access_token) {
        $location.path("login");
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
