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

angular.module('matrixWebClient')
.filter('duration', function() {
    return function(time) {
        if (!time) return;
        var t = parseInt(time / 1000);
        var s = t % 60;
        var m = parseInt(t / 60) % 60;
        var h = parseInt(t / (60 * 60)) % 24;
        var d = parseInt(t / (60 * 60 * 24));
        if (t < 60) {
            return s + "s";
        }
        if (t < 60 * 60) {
            return m + "m "; //  + s + "s";
        }
        if (t < 24 * 60 * 60) {
            return h + "h "; // + m + "m";
        }
        return d + "d "; // + h + "h";
    };
})
.filter('orderMembersList', function($sce) {
    return function(members) {
        var filtered = [];

        var displayNames = {};
        angular.forEach(members, function(value, key) {
            value["id"] = key;
            filtered.push( value );
            if (value["displayname"]) {
                if (!displayNames[value["displayname"]]) {
                    displayNames[value["displayname"]] = [];
                }
                displayNames[value["displayname"]].push(key);
            }
        });

        // FIXME: we shouldn't disambiguate displayNames on every orderMembersList
        // invocation but keep track of duplicates incrementally somewhere
        angular.forEach(displayNames, function(value, key) {
            if (value.length > 1) {
                // console.log(key + ": " + value);
                for (var i=0; i < value.length; i++) {
                    var v = value[i];
                    // FIXME: this permenantly rewrites the displayname for a given
                    // room member. which means we can't reset their name if it is
                    // no longer ambiguous!
                    members[v].displayname += " (" + v + ")";
                    // console.log(v + " " + members[v]);
                };
            }
        });

        filtered.sort(function (a, b) {
            // Sort members on their last_active absolute time
            var aLastActiveTS = 0, bLastActiveTS = 0;
            if (undefined !== a.last_active_ago) {
                aLastActiveTS = a.last_updated - a.last_active_ago;
            }
            if (undefined !== b.last_active_ago) {
                bLastActiveTS = b.last_updated - b.last_active_ago;
            }
            if (aLastActiveTS || bLastActiveTS) {
                return bLastActiveTS - aLastActiveTS;
            }
            else {
                // If they do not have last_active_ago, sort them according to their presence state
                // Online users go first amongs members who do not have last_active_ago
                var presenceLevels = {
                    offline: 1,
                    unavailable: 2,
                    online: 4,
                    free_for_chat: 3
                };
                var aPresence = (a.presence in presenceLevels) ? presenceLevels[a.presence] : 0;
                var bPresence = (b.presence in presenceLevels) ? presenceLevels[b.presence] : 0;
                return bPresence - aPresence;
            }
        });
        return filtered;
    };
})
.filter('unsafe', ['$sce', function($sce) {
    return function(text) {
        return $sce.trustAsHtml(text);
    };
}]);