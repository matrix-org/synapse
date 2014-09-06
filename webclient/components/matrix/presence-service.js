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
 * This service tracks user activity on the page to determine his presence state.
 * Any state change will be sent to the Home Server.
 */
angular.module('mPresence', [])
.service('mPresence', ['$timeout', 'matrixService', function ($timeout, matrixService) {

    // Time in ms after that a user is considered as unavailable/away
    var UNAVAILABLE_TIME = 3 * 60000; // 3 mins
   
    // The current presence state
    var state = undefined;

    var self =this;
    var timer;
    
    /**
     * Start listening the user activity to evaluate his presence state.
     * Any state change will be sent to the Home Server.
     */
    this.start = function() {
        if (undefined === state) {
            // The user is online if he moves the mouser or press a key
            document.onmousemove = resetTimer;
            document.onkeypress = resetTimer;
            
            resetTimer();
        }
    };
    
    /**
     * Stop tracking user activity
     */
    this.stop = function() {
        if (timer) {
            $timeout.cancel(timer);
            timer = undefined;
        }
        state = undefined;
    };
    
    /**
     * Get the current presence state.
     * @returns {matrixService.presence} the presence state
     */
    this.getState = function() {
        return state;
    };
    
    /**
     * Set the presence state.
     * If the state has changed, the Home Server will be notified.
     * @param {matrixService.presence} newState the new presence state
     */
    this.setState = function(newState) {
        if (newState !== state) {
            console.log("mPresence - New state: " + newState);

            state = newState;

            // Inform the HS on the new user state
            matrixService.setUserPresence(state).then(
                function() {

                },
                function(error) {
                    console.log("mPresence - Failed to send new presence state: " + JSON.stringify(error));
                });
        }
    };
    
    /**
     * Callback called when the user made no action on the page for UNAVAILABLE_TIME ms.
     * @private
     */
    function onUnvailableTimerFire() {
        self.setState(matrixService.presence.unavailable);
    }

    /**
     * Callback called when the user made an action on the page
     * @private
     */
    function resetTimer() {
        // User is still here
        self.setState(matrixService.presence.online);
        
        // Re-arm the timer
        $timeout.cancel(timer);
        timer = $timeout(onUnvailableTimerFire, UNAVAILABLE_TIME);
    }    

}]);


