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
 * This service contains multipurpose helper functions.
 */
angular.module('mUtilities', [])
.service('mUtilities', ['$q', function ($q) {
    /*
     * Gets the size of an image
     * @param {File} imageFile the file containing the image
     * @returns {promise} A promise that will be resolved by an object with 2 members:
     *   width & height
     */
    this.getImageSize = function(imageFile) {
        var deferred = $q.defer();
        
        // Load the file into an html element
        var img = document.createElement("img");
        
        var reader = new FileReader();  
        reader.onload = function(e) {   
            img.src = e.target.result;
            
            // Once ready, returns its size
            deferred.resolve({
                width: img.width,
                height: img.height
            });
        };
        reader.onerror = function(e) {
            deferred.reject(e);
        };
        reader.readAsDataURL(imageFile);
        
        return deferred.promise;
    };
}]);