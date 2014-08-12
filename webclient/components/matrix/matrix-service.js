'use strict';

angular.module('matrixService', [])
.factory('matrixService', ['$http', '$q', function($http, $q) {
        
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
        // Inject the access token
        if (!params) {
            params = {};
        }
        params.access_token = config.access_token;
        
        return doBaseRequest(config.homeserver, method, path, params, data, undefined);
    };

    var doBaseRequest = function(baseUrl, method, path, params, data, headers) {
        if (path.indexOf(prefixPath) !== 0) {
            path = prefixPath + path;
        }
        // Do not directly return the $http instance but return a promise
        // with enriched or cleaned information
        var deferred = $q.defer();
        $http({
            method: method,
            url: baseUrl + path,
            params: params,
            data: data,
            headers: headers
        })
        .success(function(data, status, headers, config) {
            // @TODO: We could detect a bad access token here and make an automatic logout
            deferred.resolve(data, status, headers, config);
        })
        .error(function(data, status, headers, config) {
            // Enrich the error callback with an human readable error reason
            var reason = data.error;
            if (!data.error) {
                reason = JSON.stringify(data);
            }
            deferred.reject(reason, data, status, headers, config);
        });

        return deferred.promise;
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
            var path = "/rooms";

            return doRequest("POST", path, undefined, {
                visibility: visibility,
                room_alias_name: room_id
            });
        },

        // List all rooms joined or been invited to
        rooms: function(from, to, limit) {
            // The REST path spec
            var path = "/im/sync";

            return doRequest("GET", path);
        },

        // Joins a room
        join: function(room_id) {
            // The REST path spec
            var path = "/rooms/$room_id/members/$user_id/state";

            // Like the cmd client, escape room ids
            room_id = encodeURIComponent(room_id);

            // Customize it
            path = path.replace("$room_id", room_id);
            path = path.replace("$user_id", config.user_id);

            return doRequest("PUT", path, undefined, {
                 membership: "join"
            });
        },

        // Invite a user to a room
        invite: function(room_id, user_id) {
            // The REST path spec
            var path = "/rooms/$room_id/members/$user_id/state";

            // Like the cmd client, escape room ids
            room_id = encodeURIComponent(room_id);

            // Customize it
            path = path.replace("$room_id", room_id);
            path = path.replace("$user_id", user_id);

            return doRequest("PUT", path, undefined, {
                 membership: "invite"
            });
        },

        // Leaves a room
        leave: function(room_id) {
            // The REST path spec
            var path = "/rooms/$room_id/members/$user_id/state";

            // Like the cmd client, escape room ids
            room_id = encodeURIComponent(room_id);

            // Customize it
            path = path.replace("$room_id", room_id);
            path = path.replace("$user_id", config.user_id);

            return doRequest("DELETE", path, undefined, undefined);
        },

        sendMessage: function(room_id, msg_id, content) {
            // The REST path spec
            var path = "/rooms/$room_id/messages/$from/$msg_id";

            if (!msg_id) {
                msg_id = "m" + new Date().getTime();
            }

            // Like the cmd client, escape room ids
            room_id = encodeURIComponent(room_id);            

            // Customize it
            path = path.replace("$room_id", room_id);
            path = path.replace("$from", config.user_id);
            path = path.replace("$msg_id", msg_id);

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

            var path = "/rooms/$room_id/members/list";
            path = path.replace("$room_id", room_id);
            return doRequest("GET", path);
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
        linkEmail: function(email) {
            var path = "/matrix/identity/api/v1/validate/email/requestToken"
            var data = "clientSecret=abc123&email=" + encodeURIComponent(email);
            var headers = {};
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            return doBaseRequest(config.identityServer, "POST", path, {}, data, headers); 
        },

        authEmail: function(userId, tokenId, code) {
            var path = "/matrix/identity/api/v1/validate/email/submitToken";
            var data = "token="+code+"&mxId="+encodeURIComponent(userId)+"&tokenId="+tokenId;
            var headers = {};
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            return doBaseRequest(config.identityServer, "POST", path, {}, data, headers); 
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
