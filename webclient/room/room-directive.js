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

angular.module('RoomController')
.directive('tabComplete', ['$timeout', function ($timeout) {
    return function (scope, element, attrs) {
        element.bind("keydown keypress", function (event) {
            // console.log("event: " + event.which);
            if (event.which === 9) {
                if (!scope.tabCompleting) { // cache our starting text
                    // console.log("caching " + element[0].value);
                    scope.tabCompleteOriginal = element[0].value;
                    scope.tabCompleting = true;
                }
                
                if (event.shiftKey) {
                    scope.tabCompleteIndex--;
                    if (scope.tabCompleteIndex < 0) {
                        scope.tabCompleteIndex = 0;
                    }
                }
                else {
                    scope.tabCompleteIndex++;
                }
                
                var searchIndex = 0;
                var targetIndex = scope.tabCompleteIndex;
                var text = scope.tabCompleteOriginal;
                
                // console.log("targetIndex: " + targetIndex + ", text=" + text);
                                    
                // FIXME: use the correct regexp to recognise userIDs
                var search = /@?([a-zA-Z0-9_\-:\.]+)$/.exec(text);
                if (targetIndex === 0) {
                    element[0].value = text;
                    
                    // Force angular to wake up and update the input ng-model by firing up input event
                    angular.element(element[0]).triggerHandler('input');
                }
                else if (search && search[1]) {
                    // console.log("search found: " + search);
                    var expansion;
                    
                    // FIXME: could do better than linear search here
                    angular.forEach(scope.members, function(item, name) {
                        if (item.displayname && searchIndex < targetIndex) {
                            if (item.displayname.toLowerCase().indexOf(search[1].toLowerCase()) === 0) {
                                expansion = item.displayname;
                                searchIndex++;
                            }
                        }
                    });
                    if (searchIndex < targetIndex) { // then search raw mxids
                        angular.forEach(scope.members, function(item, name) {
                            if (searchIndex < targetIndex) {
                                if (name.toLowerCase().indexOf(search[1].toLowerCase()) === 1) {
                                    expansion = name;
                                    searchIndex++;
                                }
                            }
                        });
                    }
                    
                    if (searchIndex === targetIndex) {
                        // xchat-style tab complete
                        if (search[0].length === text.length)
                            expansion += " : ";
                        else
                            expansion += " ";
                        element[0].value = text.replace(/@?([a-zA-Z0-9_\-:\.]+)$/, expansion);
                        // cancel blink
                        element[0].className = "";     
                        
                        // Force angular to wake up and update the input ng-model by firing up input event
                        angular.element(element[0]).triggerHandler('input');
                    }
                    else {
                        // console.log("wrapped!");
                        element[0].className = "blink"; // XXX: slightly naughty to bypass angular
                        $timeout(function() {
                             element[0].className = "";
                        }, 150);
                        element[0].value = text;
                        scope.tabCompleteIndex = 0;
                        
                        // Force angular to wake up and update the input ng-model by firing up input event
                        angular.element(element[0]).triggerHandler('input');
                    }
                }
                else {
                    scope.tabCompleteIndex = 0;
                }
                event.preventDefault();
            }
            else if (event.which !== 16 && scope.tabCompleting) {
                scope.tabCompleting = false;
                scope.tabCompleteIndex = 0;
            }
        });
    };
}])

// A directive to anchor the scroller position at the bottom when the browser is resizing.
// When the screen resizes, the bottom of the element remains the same, not the top.
.directive('keepScroll', ['$window', function($window) {
    return {
        link: function(scope, elem, attrs) {

            scope.windowHeight = $window.innerHeight;

            // Listen to window size change
            angular.element($window).bind('resize', function() {

                // If the scroller is scrolled to the bottom, there is nothing to do.
                // The browser will move it as expected
                if (elem.scrollTop() + elem.height() !== elem[0].scrollHeight) {
                    // Else, move the scroller position according to the window height change delta
                    var windowHeightDelta = $window.innerHeight - scope.windowHeight;
                    elem.scrollTop(elem.scrollTop() - windowHeightDelta);
                }

                // Store the new window height for the next screen size change
                scope.windowHeight = $window.innerHeight;
            });
        }
    };
}]);

