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

angular.module('matrixWebClient')
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
            // XXX: slightly evil hack to disable autofocus on iOS, as in general
            // it causes more problems than it fixes, by bouncing the page
            // around
            if (!/(iPad|iPhone|iPod)/g.test(navigator.userAgent)) {
                $timeout(function() { element[0].focus(); }, 0);
            }            
        }
    };
}]);