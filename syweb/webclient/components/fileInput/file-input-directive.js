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
 * Transform an element into an image file input button.
 * Watch to the passed variable change. It will contain the selected HTML5 file object.
 */
angular.module('mFileInput', [])
.directive('mFileInput', function() {
    return {
        restrict: 'A',
        transclude: 'true',
        // FIXME: add back in accept="image/*" when needed - e.g. for avatars
        template: '<div ng-transclude></div><input ng-hide="true" type="file"/>',
        scope: {
            selectedFile: '=mFileInput'
        },

        link: function(scope, element, attrs, ctrl) {
            
            // Check if HTML5 file selection is supported
            if (window.FileList) {
                element.bind("click", function() {
                    element.find("input")[0].click();
                    element.find("input").bind("change", function(e) {
                        scope.selectedFile = this.files[0];
                        scope.$apply();
                    });
                });
            }
            else {
                setTimeout(function() {
                    element.attr("disabled", true);
                    element.attr("title", "The app uses the HTML5 File API to send files. Your browser does not support it.");
                }, 1);
            }

            // Change the mouse icon on mouseover on this element
            element.css("cursor", "pointer");
      }
    };
});