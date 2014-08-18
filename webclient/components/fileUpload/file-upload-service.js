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

// TODO determine if this is really required as a separate service to matrixService.
/*
 * Upload an HTML5 file to a server
 */
angular.module('mFileUpload', [])
.service('mFileUpload', ['matrixService', '$q', function (matrixService, $q) {
        
    /*
     * Upload an HTML5 file to a server and returned a promise
     * that will provide the URL of the uploaded file.
     */
    this.uploadFile = function(file) {
        var deferred = $q.defer();
        console.log("Uploading " + file.name + "... to /matrix/content");
        matrixService.uploadContent(file).then(
            function(response) {
                console.log("   -> Successfully uploaded! Available at " + location.origin + response.data.url);
                deferred.resolve(location.origin + response.data.url);
            },
            function(error) {
                console.log("   -> Failed to upload "  + file.name);
                deferred.reject(error);
            }
        );
        
        return deferred.promise;
    };
}]);
