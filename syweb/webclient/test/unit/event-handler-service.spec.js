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

    it('should be able to get the number of joined users in a room', inject(
    function(eventHandlerService) {
        var roomId = "!foo:matrix.org";
        // set mocked data
        modelService.getRoom = function(roomId) {
            return {
                room_id: roomId,
                current_room_state: {
                    members: {
                        "@adam:matrix.org": {
                            event: {
                                content: { membership: "join" },
                                user_id: "@adam:matrix.org"
                            }
                        },
                        "@beth:matrix.org": {
                            event: {
                                content: { membership: "invite" },
                                user_id: "@beth:matrix.org"
                            }
                        },
                        "@charlie:matrix.org": {
                            event: {
                                content: { membership: "join" },
                                user_id: "@charlie:matrix.org"
                            }
                        },
                        "@danice:matrix.org": {
                            event: {
                                content: { membership: "leave" },
                                user_id: "@danice:matrix.org"
                            }
                        }
                    }
                }
            };
        }
        
        var num = eventHandlerService.getUsersCountInRoom(roomId);
        expect(num).toEqual(2);
    }));
    
    it('should be able to get a users power level', inject(
    function(eventHandlerService) {
        var roomId = "!foo:matrix.org";
        // set mocked data
        modelService.getRoom = function(roomId) {
            return {
                room_id: roomId,
                current_room_state: {
                    members: {
                        "@adam:matrix.org": {
                            event: {
                                content: { membership: "join" },
                                user_id: "@adam:matrix.org"
                            }
                        },
                        "@beth:matrix.org": {
                            event: {
                                content: { membership: "join" },
                                user_id: "@beth:matrix.org"
                            }
                        }
                    },
                    s: {
                        "m.room.power_levels": {
                            content: {
                                "@adam:matrix.org": 90,
                                "default": 50
                            }
                        }
                    },
                    state: function(type, key) { 
                        return key ? this.s[type+key] : this.s[type]
                    }
                }
            };
        };
        
        var num = eventHandlerService.getUserPowerLevel(roomId, "@beth:matrix.org");
        expect(num).toEqual(50);
        
        num = eventHandlerService.getUserPowerLevel(roomId, "@adam:matrix.org");
        expect(num).toEqual(90);
        
        num = eventHandlerService.getUserPowerLevel(roomId, "@unknown:matrix.org");
        expect(num).toEqual(50);
    }));
});
