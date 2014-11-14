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
}])
.directive('asjson', function() {
    return {
        restrict: 'A',
        require: 'ngModel',
        link: function (scope, element, attrs, ngModelCtrl) {
            function isValidJson(model) {
                var flag = true;
                try {
                    angular.fromJson(model);
                } catch (err) {
                    flag = false;
                }
                return flag;
            };

            function string2JSON(text) {
                try {
                    var j = angular.fromJson(text);
                    ngModelCtrl.$setValidity('json', true);
                    return j;
                } catch (err) {
                    //returning undefined results in a parser error as of angular-1.3-rc.0, and will not go through $validators
                    //return undefined
                    ngModelCtrl.$setValidity('json', false);
                    return text;
                }
            };

            function JSON2String(object) {
                return angular.toJson(object, true);
            };

            //$validators is an object, where key is the error
            //ngModelCtrl.$validators.json = isValidJson;

            //array pipelines
            ngModelCtrl.$parsers.push(string2JSON);
            ngModelCtrl.$formatters.push(JSON2String);
        }
    }
});
