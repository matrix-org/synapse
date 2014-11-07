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
This service manages notifications: enabling, creating and showing them. This
also contains 'bing word' logic.
*/
angular.module('notificationService', [])
.factory('notificationService', ['$timeout', function($timeout) {

    var getLocalPartFromUserId = function(user_id) {
        if (!user_id) {
            return null;
        }
        var localpartRegex = /@(.*):\w+/i
        var results = localpartRegex.exec(user_id);
        if (results && results.length == 2) {
            return results[1];
        }
        return null;
    };
    
    return {
    
        containsBingWord: function(userId, displayName, bingWords, content) {
            // case-insensitive name check for user_id OR display_name if they exist
            var userRegex = "";
            if (userId) {
                var localpart = getLocalPartFromUserId(userId);
                if (localpart) {
                    localpart = localpart.toLocaleLowerCase();
                    userRegex += "\\b" + localpart + "\\b";
                }
            }
            if (displayName) {
                displayName = displayName.toLocaleLowerCase();
                if (userRegex.length > 0) {
                    userRegex += "|";
                }
                userRegex += "\\b" + displayName + "\\b";
            }

            var regexList = [new RegExp(userRegex, 'i')];
            
            // bing word list check
            if (bingWords && bingWords.length > 0) {
                for (var i=0; i<bingWords.length; i++) {
                    var re = RegExp(bingWords[i], 'i');
                    regexList.push(re);
                }
            }
            return this.hasMatch(regexList, content);
        },
    
        hasMatch: function(regExps, content) {
            if (!content || $.type(content) != "string") {
                return false;
            }
            
            if (regExps && regExps.length > 0) {
                for (var i=0; i<regExps.length; i++) {
                    if (content.search(regExps[i]) != -1) {
                        return true;
                    }
                }
            }
            return false;
        },
        
        showNotification: function(title, body, icon, onclick) {
            var notification = new window.Notification(
                title,
                {
                    "body": body,
                    "icon": icon
                }
            );

            if (onclick) {
                notification.onclick = onclick;
            }

            $timeout(function() {
                notification.close();
            }, 5 * 1000);
        }
    };

}]);
