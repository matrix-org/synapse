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
            state_key: "@adam:matrix.org",
            type: "m.room.member"
        });
        room.current_room_state.storeStateEvent({
            content: { membership: "join" },
            user_id: "@beth:matrix.org",
            state_key: "@beth:matrix.org",
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
    
    it('should be able to get a user', inject(
    function(modelService) {
        var roomId = "!wefiohwefuiow:matrix.org";
        var userId = "@bob:matrix.org";
        
        var presenceEvent = {
            content: {
                user_id: userId,
                displayname: "Bob",
                last_active_ago: 1415981891580
            },
            type: "m.presence",
            event_id: "weofhwe@matrix.org"
        };
        
        modelService.setUser(presenceEvent);
        var user = modelService.getUser(userId);
        expect(user.event).toEqual(presenceEvent);
    }));
    
    it('should be able to create and get alias mappings.', inject(
    function(modelService) {
        var roomId = "!wefiohwefuiow:matrix.org";
        var alias = "#foobar:matrix.org";
        
        modelService.createRoomIdToAliasMapping(roomId, alias);
        
        expect(modelService.getRoomIdToAliasMapping(roomId)).toEqual(alias);
        expect(modelService.getAliasToRoomIdMapping(alias)).toEqual(roomId);
        
    }));
    
    it('should clobber alias mappings.', inject(
    function(modelService) {
        var roomId = "!wefiohwefuiow:matrix.org";
        var alias = "#foobar:matrix.org";
        var newAlias = "#foobarNEW:matrix.org";
        
        modelService.createRoomIdToAliasMapping(roomId, alias);
        
        expect(modelService.getRoomIdToAliasMapping(roomId)).toEqual(alias);
        expect(modelService.getAliasToRoomIdMapping(alias)).toEqual(roomId);
        
        modelService.createRoomIdToAliasMapping(roomId, newAlias);
        
        expect(modelService.getRoomIdToAliasMapping(roomId)).toEqual(newAlias);
        expect(modelService.getAliasToRoomIdMapping(newAlias)).toEqual(roomId);
        
    }));
    
    it('should update RoomMember when User is updated to point to the latest info.', inject(
    function(modelService) {
        var roomId = "!wefiohwefuiow:matrix.org";
        var userId = "@bob:matrix.org";
        
        var presenceEvent = {
            content: {
                user_id: userId,
                displayname: "Bob",
                last_active_ago: 1415
            },
            type: "m.presence",
            event_id: "weofhwe@matrix.org"
        };
        
        var newPresenceEvent = {
            content: {
                user_id: userId,
                displayname: "The only and only Bob",
                last_active_ago: 1900
            },
            type: "m.presence",
            event_id: "weofhtweterte@matrix.org"
        };
        
        modelService.setUser(presenceEvent);
        
        modelService.getRoom(roomId).current_room_state.storeStateEvent({
            type: "m.room.member",
            id: "fwefw:matrix.org",
            user_id: userId,
            state_key: userId,
            content: {
                membership: "join"
            }
        });
        
        var roomMember = modelService.getMember(roomId, userId);
        expect(roomMember.user.event).toEqual(presenceEvent);
        expect(roomMember.user.event.content.displayname).toEqual("Bob");
        
        modelService.setUser(newPresenceEvent);
        
        expect(roomMember.user.event.content.displayname).toEqual("The only and only Bob");
        
    }));
    
    it('should normalise power levels between 0-100.', inject(
    function(modelService) {
        var roomId = "!foo:matrix.org";
        
        var room = modelService.getRoom(roomId);
        room.current_room_state.storeStateEvent({
            content: { membership: "join" },
            user_id: "@adam:matrix.org",
            state_key: "@adam:matrix.org",
            type: "m.room.member"
        });
        room.current_room_state.storeStateEvent({
            content: { membership: "join" },
            user_id: "@beth:matrix.org",
            state_key: "@beth:matrix.org",
            type: "m.room.member"
        });
        room.current_room_state.storeStateEvent({
            content: {
                "@adam:matrix.org": 1000,
                "default": 500
            },
            user_id: "@adam:matrix.org",
            type: "m.room.power_levels"
        });
        
        var roomMember = modelService.getMember(roomId, "@beth:matrix.org");
        expect(roomMember.power_level).toEqual(500);
        expect(roomMember.power_level_norm).toEqual(50);

        
    }));
});
