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
 * Upload an HTML5 file to a server
 */
angular.module('mFileUpload', [])
.service('mFileUpload', ['$http', '$q', function ($http, $q) {
        
    /*
     * Upload an HTML5 file to a server and returned a promise
     * that will provide the URL of the uploaded file.
     */
    this.uploadFile = function(file) {
        var deferred = $q.defer();
        
        // @TODO: This service runs with the do_POST hacky implementation of /synapse/demos/webserver.py.
        // This is temporary until we have a true file upload service
        console.log("Uploading " + file.name + "...");
        $http.post(file.name, file)
        .success(function(data, status, headers, config) {
            deferred.resolve(location.origin + data.url);
            console.log("   -> Successfully uploaded! Available at " + location.origin + data.url);
        }).
        error(function(data, status, headers, config) {
            console.log("   -> Failed to upload"  + file.name);
            deferred.reject();
        });
        
        return deferred.promise;
    };
}]);