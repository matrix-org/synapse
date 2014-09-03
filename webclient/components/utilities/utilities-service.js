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
 * This service contains multipurpose helper functions.
 */
angular.module('mUtilities', [])
.service('mUtilities', ['$q', function ($q) {
    /*
     * Get the size of an image
     * @param {File|Blob} imageFile the file containing the image
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
            img.onload = function() {
                deferred.resolve({
                    width: img.width,
                    height: img.height
                });
            };
            img.onerror = function(e) {
                deferred.reject(e);
            };
        };
        reader.onerror = function(e) {
            deferred.reject(e);
        };
        reader.readAsDataURL(imageFile);
        
        return deferred.promise;
    };

    /*
     * Resize the image to fit in a square of the side maxSize. 
     * The aspect ratio is kept. The returned image data uses JPEG compression.
     * Source: http://hacks.mozilla.org/2011/01/how-to-develop-a-html5-image-uploader/
     * @param {File} imageFile the file containing the image 
     * @param {Integer} maxSize the max side size 
     * @returns {promise} A promise that will be resolved by a Blob object containing
     *   the resized image data
     */
    this.resizeImage = function(imageFile, maxSize) {
        var self = this;
        var deferred = $q.defer();

        var canvas = document.createElement("canvas");

        var img = document.createElement("img");
        var reader = new FileReader();  
        reader.onload = function(e) {

            img.src = e.target.result;
            
            // Once ready, returns its size
            img.onload = function() {
                var ctx = canvas.getContext("2d");
                ctx.drawImage(img, 0, 0);

                var MAX_WIDTH = maxSize;
                var MAX_HEIGHT = maxSize;
                var width = img.width;
                var height = img.height;

                if (width > height) {
                    if (width > MAX_WIDTH) {
                        height *= MAX_WIDTH / width;
                        width = MAX_WIDTH;
                    }
                } else {
                    if (height > MAX_HEIGHT) {
                        width *= MAX_HEIGHT / height;
                        height = MAX_HEIGHT;
                    }
                }
                canvas.width = width;
                canvas.height = height;
                var ctx = canvas.getContext("2d");
                ctx.drawImage(img, 0, 0, width, height);

                // Extract image data in the same format as the original one.
                // The 0.7 compression value will work with formats that supports it like JPEG.
                var dataUrl = canvas.toDataURL(imageFile.type, 0.7); 
                deferred.resolve(self.dataURItoBlob(dataUrl));
            };
            img.onerror = function(e) {
                deferred.reject(e);
            };
        };
        reader.onerror = function(e) {
            deferred.reject(e);
        };
        reader.readAsDataURL(imageFile);

        return deferred.promise;
    };

    /*
     * Convert a dataURI string to a blob 
     * Source: http://stackoverflow.com/a/17682951
     * @param {String} dataURI the dataURI can be a base64 encoded string or an URL encoded string.
     * @returns {Blob} the blob
     */
    this.dataURItoBlob = function(dataURI) {
        // convert base64 to raw binary data held in a string
        // doesn't handle URLEncoded DataURIs
        var byteString;
        if (dataURI.split(',')[0].indexOf('base64') >= 0)
            byteString = atob(dataURI.split(',')[1]);
        else
            byteString = unescape(dataURI.split(',')[1]);
        // separate out the mime component
        var mimeString = dataURI.split(',')[0].split(':')[1].split(';')[0];

        // write the bytes of the string to an ArrayBuffer
        var ab = new ArrayBuffer(byteString.length);
        var ia = new Uint8Array(ab);
        for (var i = 0; i < byteString.length; i++) {
            ia[i] = byteString.charCodeAt(i);
        }

        // write the ArrayBuffer to a blob, and you're done
        return new Blob([ab],{type: mimeString});
    };

}]);