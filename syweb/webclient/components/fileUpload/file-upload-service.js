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

// TODO determine if this is really required as a separate service to matrixService.
/*
 * Upload an HTML5 file to a server
 */
angular.module('mFileUpload', ['matrixService', 'mUtilities'])
.service('mFileUpload', ['$q', 'matrixService', 'mUtilities', function ($q, matrixService, mUtilities) {
        
    /*
     * Upload an HTML5 file or blob to a server and returned a promise
     * that will provide the URL of the uploaded file.
     * @param {File|Blob} file the file data to send
     */
    this.uploadFile = function(file) {
        var deferred = $q.defer();
        console.log("Uploading " + file.name + "... to /_matrix/content");
        matrixService.uploadContent(file).then(
            function(response) {
                var content_url = response.data.content_token;
                console.log("   -> Successfully uploaded! Available at " + content_url);
                deferred.resolve(content_url);
            },
            function(error) {
                console.log("   -> Failed to upload "  + file.name);
                deferred.reject(error);
            }
        );
        
        return deferred.promise;
    };
    
    /*
     * Upload an file plus generate a thumbnail of it (if possible) and upload it so that
     * we will have all information to fulfill an file/image message request
     * @param {File} file the file to send
     * @param {Integer} thumbnailSize the max side size of the thumbnail to create
     * @returns {promise} A promise that will be resolved by a message object
     *   ready to be send with the Matrix API
     */
    this.uploadFileAndThumbnail = function(file, thumbnailSize) {
        var self = this;
        var deferred = $q.defer();

        console.log("uploadFileAndThumbnail " + file.name + " - thumbnailSize: " + thumbnailSize);

        // The message structure that will be returned in the promise will look something like:
        var message = {
/*            
            msgtype: "m.image",
            url: undefined,
            body: "Image",
            info: {
                size: undefined,
                  w: undefined,
                  h: undefined,
                mimetype: undefined
            },            
            thumbnail_url: undefined,
            thumbnail_info: {
                size: undefined,
                w: undefined,
                h: undefined,
                mimetype: undefined
            }
*/            
        };

        if (file.type.indexOf("image/") === 0) {
            // it's an image - try to do clientside thumbnailing.
            mUtilities.getImageSize(file).then(
                function(size) {
                    console.log("image size: " + JSON.stringify(size));

                    // The final operation: send file
                    var uploadImage = function() {
                        self.uploadFile(file).then(
                            function(url) {
                                // Update message metadata
                                message.url = url;
                                message.msgtype = "m.image";
                                message.body = file.name;
                                message.info = {
                                    size: file.size,
                                    w: size.width,
                                    h: size.height,
                                    mimetype: file.type
                                };

                                // If there is no thumbnail (because the original image is smaller than thumbnailSize),
                                // reuse the original image info for thumbnail data
                                if (!message.thumbnail_url) {
                                    message.thumbnail_url = message.url;
                                    message.thumbnail_info = message.info;
                                }

                                // We are done
                                deferred.resolve(message);
                            },
                            function(error) {
                                console.log("      -> Can't upload image");
                                deferred.reject(error); 
                            }
                        );
                    };

                    // Create a thumbnail if the image size exceeds thumbnailSize
                    if (Math.max(size.width, size.height) > thumbnailSize) {
                        console.log("    Creating thumbnail...");
                        mUtilities.resizeImage(file, thumbnailSize).then(
                            function(thumbnailBlob) {

                                // Get its size
                                mUtilities.getImageSize(thumbnailBlob).then(
                                    function(thumbnailSize) {
                                        console.log("      -> Thumbnail size: " + JSON.stringify(thumbnailSize));

                                        // Upload it to the server
                                        self.uploadFile(thumbnailBlob).then(
                                            function(thumbnailUrl) {

                                                // Update image message data
                                                message.thumbnail_url = thumbnailUrl;
                                                message.thumbnail_info = {
                                                    size: thumbnailBlob.size,
                                                    w: thumbnailSize.width,
                                                    h: thumbnailSize.height,
                                                    mimetype: thumbnailBlob.type
                                                };

                                                // Then, upload the original image
                                                uploadImage();
                                            },
                                            function(error) {
                                                console.log("      -> Can't upload thumbnail");
                                                deferred.reject(error); 
                                            }
                                        );
                                    },
                                    function(error) {
                                        console.log("      -> Failed to get thumbnail size");
                                        deferred.reject(error); 
                                    }
                                );

                            },
                            function(error) {
                                console.log("      -> Failed to create thumbnail: " + error);
                                deferred.reject(error); 
                            }
                        );
                    }
                    else {
                        // No need of thumbnail
                        console.log("   Thumbnail is not required");
                        uploadImage();
                    }

                },
                function(error) {
                    console.log("   -> Failed to get image size");
                    deferred.reject(error); 
                }
            );
        }
        else {
            // it's a random file - just upload it.
            self.uploadFile(file).then(
                function(url) {
                    // Update message metadata
                    message.url = url;
                    message.msgtype = "m.file";
                    message.body = file.name;
                    message.info = {
                        size: file.size,
                        mimetype: file.type
                    };

                    // We are done
                    deferred.resolve(message);
                },
                function(error) {
                    console.log("      -> Can't upload file");
                    deferred.reject(error); 
                }
            );
        }

        return deferred.promise;
    };

}]);
