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
});
