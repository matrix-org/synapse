describe('EventHandlerService', function() {
    var scope;
    
    var modelService = {};

    // setup the service and mocked dependencies
    beforeEach(function() {
        // dependencies
        module('matrixService');
        module('notificationService');
        module('mPresence');
        
        // cleanup mocked methods
        modelService = {};
        
        // mocked dependencies
        module(function ($provide) {
          $provide.value('modelService', modelService);
        });
        
        // tested service
        module('eventHandlerService');
    });
    
    beforeEach(inject(function($rootScope) {
        scope = $rootScope;
    }));

    
});
