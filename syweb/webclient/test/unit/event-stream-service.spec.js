describe('EventStreamService', function() {
    var q, scope;

    var testInitialSync, testEventStream;

    var matrixService = {
        initialSync: function(limit, feedback) {
            var defer = q.defer();
            defer.resolve(testInitialSync);
            return defer.promise;
        },
        getEventStream: function(from, svrTimeout, cliTimeout) {
            var defer = q.defer();
            defer.resolve(testEventStream);
            return defer.promise;
        }
    };
    
    var eventHandlerService = {
        handleInitialSyncDone: function(response) {
        
        },
        
        handleEvents: function(chunk, isLive) {
        
        }
    };

    // setup the dependencies
    beforeEach(function() {
    
        // reset test data
        testInitialSync = {
            data: {
                end: "foo",
                presence: [],
                rooms: []
            }
        };
        testEventStream = {
            data: {
                start: "foostart",
                end: "fooend",
                chunk: []
            }
        };
    
        // dependencies
        module(function ($provide) {
          $provide.value('matrixService', matrixService);
          $provide.value('eventHandlerService', eventHandlerService);
        });
        
        // tested service
        module('eventStreamService');
    });
    
    beforeEach(inject(function($q, $rootScope) {
        q = $q;
        scope = $rootScope;
    }));

    it('should start with /initialSync then go onto /events', inject(
    function(eventStreamService) {
        spyOn(eventHandlerService, "handleInitialSyncDone");
        spyOn(eventHandlerService, "handleEvents");
        eventStreamService.resume();
        scope.$apply(); // initialSync request
        expect(eventHandlerService.handleInitialSyncDone).toHaveBeenCalledWith(testInitialSync);
        expect(eventHandlerService.handleEvents).toHaveBeenCalledWith(testEventStream.data.chunk, true);
    }));
    
    it('should use the end token in /initialSync for the next /events request', inject(
    function(eventStreamService) {
        spyOn(matrixService, "getEventStream").and.callThrough();
        eventStreamService.resume();
        scope.$apply(); // initialSync request
        expect(matrixService.getEventStream).toHaveBeenCalledWith("foo", eventStreamService.SERVER_TIMEOUT, eventStreamService.CLIENT_TIMEOUT);
    }));
});
