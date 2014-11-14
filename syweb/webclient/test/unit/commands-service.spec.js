describe('CommandsService', function() {
    var scope;
    var roomId = "!dlwifhweu:localhost";
    
    var testPowerLevelsEvent, testMatrixServicePromise;
    
    var matrixService = { // these will be spyed on by jasmine, hence stub methods
        setDisplayName: function(args){},
        kick: function(args){},
        ban: function(args){},
        unban: function(args){},
        setUserPowerLevel: function(args){}
    };
    
    var modelService = {
        getRoom: function(roomId) {
            return {
                room_id: roomId,
                current_room_state: {
                    events: {
                        "m.room.power_levels": testPowerLevelsEvent
                    },
                    state: function(type, key) {
                        return key ? this.events[type+key] : this.events[type];
                    }
                }
            };
        }
    };
    
    
    // helper function for asserting promise outcomes
    NOTHING = "[Promise]";
    RESOLVED = "[Resolved promise]";
    REJECTED = "[Rejected promise]";
    var expectPromise = function(promise, expects) {
        var value = NOTHING;
        promise.then(function(result) {
            value = RESOLVED;
        }, function(fail) {
            value = REJECTED;
        });
        scope.$apply();
        expect(value).toEqual(expects);
    };

    // setup the service and mocked dependencies
    beforeEach(function() {
        
        // set default mock values
        testPowerLevelsEvent = {
            content: {
                default: 50
            },
            user_id: "@foo:bar",
            room_id: roomId
        }
        
        // mocked dependencies
        module(function ($provide) {
          $provide.value('matrixService', matrixService);
          $provide.value('modelService', modelService);
        });
        
        // tested service
        module('commandsService');
    });
    
    beforeEach(inject(function($rootScope, $q) {
        scope = $rootScope;
        testMatrixServicePromise = $q.defer();
    }));

    it('should reject a no-arg "/nick".', inject(
    function(commandsService) {
        var promise = commandsService.processInput(roomId, "/nick");
        expectPromise(promise, REJECTED);
    }));
    
    it('should be able to set a /nick with multiple words.', inject(
    function(commandsService) {
        spyOn(matrixService, 'setDisplayName').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/nick Bob Smith");
        expect(matrixService.setDisplayName).toHaveBeenCalledWith("Bob Smith");
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /kick a user without a reason.', inject(
    function(commandsService) {
        spyOn(matrixService, 'kick').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/kick @bob:matrix.org");
        expect(matrixService.kick).toHaveBeenCalledWith(roomId, "@bob:matrix.org", undefined);
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /kick a user with a reason.', inject(
    function(commandsService) {
        spyOn(matrixService, 'kick').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/kick @bob:matrix.org he smells");
        expect(matrixService.kick).toHaveBeenCalledWith(roomId, "@bob:matrix.org", "he smells");
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /ban a user without a reason.', inject(
    function(commandsService) {
        spyOn(matrixService, 'ban').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/ban @bob:matrix.org");
        expect(matrixService.ban).toHaveBeenCalledWith(roomId, "@bob:matrix.org", undefined);
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /ban a user with a reason.', inject(
    function(commandsService) {
        spyOn(matrixService, 'ban').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/ban @bob:matrix.org he smells");
        expect(matrixService.ban).toHaveBeenCalledWith(roomId, "@bob:matrix.org", "he smells");
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /unban a user.', inject(
    function(commandsService) {
        spyOn(matrixService, 'unban').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/unban @bob:matrix.org");
        expect(matrixService.unban).toHaveBeenCalledWith(roomId, "@bob:matrix.org");
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /op a user.', inject(
    function(commandsService) {
        spyOn(matrixService, 'setUserPowerLevel').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/op @bob:matrix.org 50");
        expect(matrixService.setUserPowerLevel).toHaveBeenCalledWith(roomId, "@bob:matrix.org", 50, testPowerLevelsEvent);
        expect(promise).toBe(testMatrixServicePromise);
    }));
    
    it('should be able to /deop a user.', inject(
    function(commandsService) {
        spyOn(matrixService, 'setUserPowerLevel').and.returnValue(testMatrixServicePromise);
        var promise = commandsService.processInput(roomId, "/deop @bob:matrix.org");
        expect(matrixService.setUserPowerLevel).toHaveBeenCalledWith(roomId, "@bob:matrix.org", undefined, testPowerLevelsEvent);
        expect(promise).toBe(testMatrixServicePromise);
    }));
});
