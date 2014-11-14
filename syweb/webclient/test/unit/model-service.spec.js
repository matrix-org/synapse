describe('ModelService', function() {

    // setup the dependencies
    beforeEach(function() {
        // dependencies
        module('matrixService');
        
        // tested service
        module('modelService');
    });

    it('should be able to get a member in a room', inject(
    function(modelService) {
        var roomId = "!wefiohwefuiow:matrix.org";
        var userId = "@bob:matrix.org";
        
        modelService.getRoom(roomId).current_room_state.storeStateEvent({
            type: "m.room.member",
            id: "fwefw:matrix.org",
            user_id: userId,
            state_key: userId,
            content: {
                membership: "join"
            }
        });
        
        var user = modelService.getMember(roomId, userId);
        expect(user.event.state_key).toEqual(userId);
    }));
    
    it('should be able to get a users power level', inject(
    function(modelService) {
        var roomId = "!foo:matrix.org";
        
        var room = modelService.getRoom(roomId);
        room.current_room_state.storeStateEvent({
            content: { membership: "join" },
            user_id: "@adam:matrix.org",
            type: "m.room.member"
        });
        room.current_room_state.storeStateEvent({
            content: { membership: "join" },
            user_id: "@beth:matrix.org",
            type: "m.room.member"
        });
        room.current_room_state.storeStateEvent({
            content: {
                "@adam:matrix.org": 90,
                "default": 50
            },
            user_id: "@adam:matrix.org",
            type: "m.room.power_levels"
        });
        
        var num = modelService.getUserPowerLevel(roomId, "@beth:matrix.org");
        expect(num).toEqual(50);
        
        num = modelService.getUserPowerLevel(roomId, "@adam:matrix.org");
        expect(num).toEqual(90);
        
        num = modelService.getUserPowerLevel(roomId, "@unknown:matrix.org");
        expect(num).toEqual(50);
    }));
});
