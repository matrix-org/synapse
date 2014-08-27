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
This service wraps up Matrix API calls. 

This serves to isolate the caller from changes to the underlying url paths, as
well as attach common params (e.g. access_token) to requests.
*/
angular.module('matrixService', [])
.factory('matrixService', ['$http', '$q', '$rootScope', function($http, $q, $rootScope) {
        
   /* 
    * Permanent storage of user information
    * The config contains:
    *    - homeserver url
    *    - Identity server url
    *    - user_id
    *    - access_token
    *    - version: the version of this cache
    */    
    var config;
    
    // Current version of permanent storage
    var configVersion = 0;
    var prefixPath = "/matrix/client/api/v1";
    var MAPPING_PREFIX = "alias_for_";

    var doRequest = function(method, path, params, data) {
        if (!config) {
            console.warn("No config exists. Cannot perform request to "+path);
            return;
        }
    
        // Inject the access token
        if (!params) {
            params = {};
        }
        
        params.access_token = config.access_token;
        
        if (path.indexOf(prefixPath) !== 0) {
            path = prefixPath + path;
        }
        
        return doBaseRequest(config.homeserver, method, path, params, data, undefined);
    };

    var doBaseRequest = function(baseUrl, method, path, params, data, headers, $httpParams) {

        var request = {
            method: method,
            url: baseUrl + path,
            params: params,
            data: data,
            headers: headers
        };

        // Add additional $http parameters
        if ($httpParams) {
            angular.extend(request, $httpParams);
        }

        return $http(request);
    };

    return {
        /****** Home server API ******/
        prefix: prefixPath,

        // Register an user
        register: function(user_name, password) {
            // The REST path spec
            var path = "/register";

            return doRequest("POST", path, undefined, {
                 user_id: user_name,
                 password: password
            });
        },

        // Create a room
        create: function(room_id, visibility) {
            // The REST path spec
            var path = "/createRoom";

            return doRequest("POST", path, undefined, {
                visibility: visibility,
                room_alias_name: room_id
            });
        },

        // List all rooms joined or been invited to
        rooms: function(from, to, limit) {
            // The REST path spec
            var path = "/initialSync";

            return doRequest("GET", path);
        },

        // Joins a room
        join: function(room_id) {
            return this.membershipChange(room_id, undefined, "join");
        },

        joinAlias: function(room_alias) {
            var path = "/join/$room_alias";
            room_alias = encodeURIComponent(room_alias);

            path = path.replace("$room_alias", room_alias);

            return doRequest("PUT", path, undefined, {});
        },

        // Invite a user to a room
        invite: function(room_id, user_id) {
            return this.membershipChange(room_id, user_id, "invite");
        },

        // Leaves a room
        leave: function(room_id) {
            return this.membershipChange(room_id, undefined, "leave");
        },

        membershipChange: function(room_id, user_id, membershipValue) {
            // The REST path spec
            var path = "/rooms/$room_id/$membership";
            path = path.replace("$room_id", encodeURIComponent(room_id));
            path = path.replace("$membership", encodeURIComponent(membershipValue));

            var data = {};
            if (user_id !== undefined) {
                data = { user_id: user_id };
            }

            // TODO: Use PUT with transaction IDs
            return doRequest("POST", path, undefined, data);
        },

        // Retrieves the room ID corresponding to a room alias
        resolveRoomAlias:function(room_alias) {
            var path = "/matrix/client/api/v1/ds/room/$room_alias";
            room_alias = encodeURIComponent(room_alias);

            path = path.replace("$room_alias", room_alias);

            return doRequest("GET", path, undefined, {});
        },

        sendMessage: function(room_id, txn_id, content) {
            // The REST path spec
            var path = "/rooms/$room_id/send/m.room.message/$txn_id";

            if (!txn_id) {
                txn_id = "m" + new Date().getTime();
            }

            // Like the cmd client, escape room ids
            room_id = encodeURIComponent(room_id);            

            // Customize it
            path = path.replace("$room_id", room_id);
            path = path.replace("$txn_id", txn_id);

            return doRequest("PUT", path, undefined, content);
        },

        // Send a text message
        sendTextMessage: function(room_id, body, msg_id) {
            var content = {
                 msgtype: "m.text",
                 body: body
            };

            return this.sendMessage(room_id, msg_id, content);
        },

        // Send an image message
        sendImageMessage: function(room_id, image_url, image_body, msg_id) {
            var content = {
                 msgtype: "m.image",
                 url: image_url,
                 body: image_body
            };

            return this.sendMessage(room_id, msg_id, content);
        },

        // Send an emote message
        sendEmoteMessage: function(room_id, body, msg_id) {
            var content = {
                 msgtype: "m.emote",
                 body: body
            };

            return this.sendMessage(room_id, msg_id, content);
        },

        // get a snapshot of the members in a room.
        getMemberList: function(room_id) {
            // Like the cmd client, escape room ids
            room_id = encodeURIComponent(room_id);

            var path = "/rooms/$room_id/members";
            path = path.replace("$room_id", room_id);
            return doRequest("GET", path);
        },
        
        paginateBackMessages: function(room_id, from_token, limit) {
            var path = "/rooms/$room_id/messages";
            path = path.replace("$room_id", room_id);
            var params = {
                from: from_token,
                limit: limit,
                dir: 'b'
            };
            return doRequest("GET", path, params);
        },

        // get a list of public rooms on your home server
        publicRooms: function() {
            var path = "/public/rooms"
            return doRequest("GET", path);
        },
        
        // get a display name for this user ID
        getDisplayName: function(userId) {
            return this.getProfileInfo(userId, "displayname");
        },

        // get the profile picture url for this user ID
        getProfilePictureUrl: function(userId) {
            return this.getProfileInfo(userId, "avatar_url");
        },

        // update your display name
        setDisplayName: function(newName) {
            var content = {
                displayname: newName
            };
            return this.setProfileInfo(content, "displayname");
        },

        // update your profile picture url
        setProfilePictureUrl: function(newUrl) {
            var content = {
                avatar_url: newUrl
            };
            return this.setProfileInfo(content, "avatar_url");
        },

        setProfileInfo: function(data, info_segment) {
            var path = "/profile/$user/" + info_segment;
            path = path.replace("$user", config.user_id);
            return doRequest("PUT", path, undefined, data);
        },

        getProfileInfo: function(userId, info_segment) {
            var path = "/profile/$user_id/" + info_segment;
            path = path.replace("$user_id", userId);
            return doRequest("GET", path);
        },
        
        login: function(userId, password) {
            // TODO We should be checking to make sure the client can support
            // logging in to this HS, else use the fallback.
            var path = "/login";
            var data = {
                "type": "m.login.password",
                "user": userId,
                "password": password  
            };
            return doRequest("POST", path, undefined, data);
        },

        // hit the Identity Server for a 3PID request.
        linkEmail: function(email, clientSecret, sendAttempt) {
            var path = "/matrix/identity/api/v1/validate/email/requestToken"
            var data = "clientSecret="+clientSecret+"&email=" + encodeURIComponent(email)+"&sendAttempt="+sendAttempt;
            var headers = {};
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            return doBaseRequest(config.identityServer, "POST", path, {}, data, headers); 
        },

        authEmail: function(clientSecret, tokenId, code) {
            var path = "/matrix/identity/api/v1/validate/email/submitToken";
            var data = "token="+code+"&sid="+tokenId+"&clientSecret="+clientSecret;
            var headers = {};
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            return doBaseRequest(config.identityServer, "POST", path, {}, data, headers);
        },

        bindEmail: function(userId, tokenId, clientSecret) {
            var path = "/matrix/identity/api/v1/3pid/bind";
            var data = "mxid="+encodeURIComponent(userId)+"&sid="+tokenId+"&clientSecret="+clientSecret;
            var headers = {};
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            return doBaseRequest(config.identityServer, "POST", path, {}, data, headers); 
        },
        
        uploadContent: function(file) {
            var path = "/matrix/content";
            var headers = {
                "Content-Type": undefined // undefined means angular will figure it out
            };
            var params = {
                access_token: config.access_token
            };

            // If the file is actually a Blob object, prevent $http from JSON-stringified it before sending
            // (Equivalent to jQuery ajax processData = false)
            var $httpParams;
            if (file instanceof Blob) {
                $httpParams = {
                    transformRequest: angular.identity
                };
            }

            return doBaseRequest(config.homeserver, "POST", path, params, file, headers, $httpParams);
        },
        
        // start listening on /events
        getEventStream: function(from, timeout) {
            var path = "/events";
            var params = {
                from: from,
                timeout: timeout
            };
            return doRequest("GET", path, params);
        },

        // Indicates if user authentications details are stored in cache
        isUserLoggedIn: function() {
            var config = this.config();

            // User is considered logged in if his cache is not empty and contains
            // an access token
            if (config && config.access_token) {
                return true;
            }
            else {
                return false;
            }
        },
        
        // Enum of presence state
        presence: {
            offline: "offline",
            unavailable: "unavailable",
            online: "online",
            free_for_chat: "free_for_chat"
        },
        
        // Set the logged in user presence state
        setUserPresence: function(presence) {
            var path = "/presence/$user_id/status";
            path = path.replace("$user_id", config.user_id);
            return doRequest("PUT", path, undefined, {
                state: presence
            });
        },

        /****** Permanent storage of user information ******/
        
        // Returns the current config
        config: function() {
            if (!config) {
                config = localStorage.getItem("config");
                if (config) {
                    config = JSON.parse(config);

                    // Reset the cache if the version loaded is not the expected one
                    if (configVersion !== config.version) {
                        config = undefined;
                        this.saveConfig();
                    }
                }
            }
            return config;
        },
        
        // Set a new config (Use saveConfig to actually store it permanently)
        setConfig: function(newConfig) {
            config = newConfig;
            console.log("new IS: "+config.identityServer);
        },
        
        // Commits config into permanent storage
        saveConfig: function() {
            config.version = configVersion;
            localStorage.setItem("config", JSON.stringify(config));
        },
        
        createRoomIdToAliasMapping: function(roomId, alias) {
            localStorage.setItem(MAPPING_PREFIX+roomId, alias);
        },
        
        getRoomIdToAliasMapping: function(roomId) {
            return localStorage.getItem(MAPPING_PREFIX+roomId);
        }

    };
}]);
