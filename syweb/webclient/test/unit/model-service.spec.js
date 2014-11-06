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
        expect(user.state_key).toEqual(userId);
    }));
});
