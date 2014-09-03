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

angular.module('RecentsController')
.filter('orderRecents', function() {
    return function(rooms) {

        // Transform the dict into an array
        // The key, room_id, is already in value objects
        var filtered = [];
        angular.forEach(rooms, function(value, key) {
            filtered.push( value );
        });

        // And time sort them
        // The room with the lastest message at first
        filtered.sort(function (a, b) {
            // Invite message does not have a body message nor ts
            // Puth them at the top of the list
            if (undefined === a.lastMsg) {
                return -1;
            }
            else if (undefined === b.lastMsg) {
                return 1;
            }
            else {
                return b.lastMsg.ts - a.lastMsg.ts;
            }
        });
        return filtered;
    };
});