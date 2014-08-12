/*
 * Main controller
 */

'use strict';

angular.module('MatrixWebClientController', ['matrixService'])
.controller('MatrixWebClientController', ['$scope', '$location', '$rootScope', 'matrixService',
                               function($scope, $location, $rootScope, matrixService) {
         
    // Check current URL to avoid to display the logout button on the login page
    $scope.location = $location.path();
    
    // Update the location state when the ng location changed
    $rootScope.$on('$routeChangeSuccess', function (event, current, previous) {
        $scope.location = $location.path();
    });
    
    
    // Manage the display of the current config
    $scope.config;
    
    // Toggles the config display
    $scope.showConfig = function() {
        if ($scope.config) {
            $scope.config = undefined;
        }
        else {
            $scope.config = matrixService.config();        
        }
    };    
    
    
    // Logs the user out 
    $scope.logout = function() {
        // Clean permanent data
        matrixService.setConfig({});
        matrixService.saveConfig();
        
        // And go to the login page
        $location.path("login");
    };    
                          
}]);

   