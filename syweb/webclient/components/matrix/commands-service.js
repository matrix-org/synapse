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
This service contains logic for parsing and performing IRC style commands.
*/
angular.module('commandsService', [])
.factory('commandsService', ['$q', '$location', 'matrixService', 'modelService', function($q, $location, matrixService, modelService) {

    // create a rejected promise with the given message
    var reject = function(msg) {
        var deferred = $q.defer();
        deferred.reject({
            data: {
                error: msg
            }
        });
        return deferred.promise;
    };
    
    // Change your nickname
    var doNick = function(room_id, args) {
        if (args) {
            return matrixService.setDisplayName(args);                     
        }
        return reject("Usage: /nick <display_name>");
    };
    
    // Join a room
    var doJoin = function(room_id, args) {
        if (args) {
            var matches = args.match(/^(\S+)$/);
            if (matches) {
                var room_alias = matches[1];
                $location.url("room/" + room_alias);
                // NB: We don't need to actually do the join, since that happens
                // automatically if we are not joined onto a room already when
                // the page loads.
                return reject("Joining "+room_alias);
            }
        }
        return reject("Usage: /join <room_alias>");
    };
    
    // Kick a user from the room with an optional reason
    var doKick = function(room_id, args) {
        if (args) {
            var matches = args.match(/^(\S+?)( +(.*))?$/);
            if (matches) {
                return matrixService.kick(room_id, matches[1], matches[3]);
            }
        }
        return reject("Usage: /kick <userId> [<reason>]");
    };
    
    // Ban a user from the room with an optional reason
    var doBan = function(room_id, args) {
        if (args) {
            var matches = args.match(/^(\S+?)( +(.*))?$/);
            if (matches) {
                return matrixService.ban(room_id, matches[1], matches[3]);
            }
        }
        return reject("Usage: /ban <userId> [<reason>]");
    };
    
    // Unban a user from the room
    var doUnban = function(room_id, args) {
        if (args) {
            var matches = args.match(/^(\S+)$/);
            if (matches) {
                // Reset the user membership to "leave" to unban him
                return matrixService.unban(room_id, matches[1]);
            }
        }
        return reject("Usage: /unban <userId>");
    };
    
    // Define the power level of a user
    var doOp = function(room_id, args) {
        if (args) {
            var matches = args.match(/^(\S+?)( +(\d+))?$/);
            var powerLevel = 50; // default power level for op
            if (matches) {
                var user_id = matches[1];
                if (matches.length === 4 && undefined !== matches[3]) {
                    powerLevel = parseInt(matches[3]);
                }
                if (powerLevel !== NaN) {
                    var powerLevelEvent = modelService.getRoom(room_id).current_room_state.state("m.room.power_levels");
                    return matrixService.setUserPowerLevel(room_id, user_id, powerLevel, powerLevelEvent);
                }
            }
        }
        return reject("Usage: /op <userId> [<power level>]");
    };
    
    // Reset the power level of a user
    var doDeop = function(room_id, args) {
        if (args) {
            var matches = args.match(/^(\S+)$/);
            if (matches) {
                var powerLevelEvent = modelService.getRoom(room_id).current_room_state.state("m.room.power_levels");
                return matrixService.setUserPowerLevel(room_id, args, undefined, powerLevelEvent);
            }
        }
        return reject("Usage: /deop <userId>");
    };


    var commands = {
        "nick": doNick,
        "join": doJoin,
        "kick": doKick,
        "ban": doBan,
        "unban": doUnban,
        "op": doOp,
        "deop": doDeop
    };
    
    return {
    
        /**
         * Process the given text for commands and perform them.
         * @param {String} roomId The room in which the input was performed.
         * @param {String} input The raw text input by the user.
         * @return {Promise} A promise of the pending command, or null if the 
         *                   input is not a command.
         */
        processInput: function(roomId, input) {
            // trim any trailing whitespace, as it can confuse the parser for 
            // IRC-style commands
            input = input.replace(/\s+$/, "");
            if (input[0] === "/" && input[1] !== "/") {
                var bits = input.match(/^(\S+?)( +(.*))?$/);
                var cmd = bits[1].substring(1);
                var args = bits[3];
                if (commands[cmd]) {
                    return commands[cmd](roomId, args);
                }
                return reject("Unrecognised IRC-style command: " + cmd); 
            }
            return null; // not a command
        }
    
    };

}]);

