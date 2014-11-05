describe('MatrixService', function() {
    var scope, httpBackend;
    var BASE = "http://example.com";
    var PREFIX = "/_matrix/client/api/v1";
    var URL = BASE + PREFIX;
    var roomId = "!wejigf387t34:matrix.org";
    
    beforeEach(module('matrixService'));

    beforeEach(inject(function($rootScope, $httpBackend) {
        httpBackend = $httpBackend;
        scope = $rootScope;
    }));

    afterEach(function() {
        httpBackend.verifyNoOutstandingExpectation();
        httpBackend.verifyNoOutstandingRequest();
    });

    it('should be able to POST /createRoom with an alias', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var alias = "flibble";
        matrixService.create(alias).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(URL + "/createRoom?access_token=foobar",
            {
                room_alias_name: alias
            })
            .respond({});
        httpBackend.flush();
    }));

    it('should be able to GET /initialSync', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var limit = 15;
        matrixService.initialSync(limit).then(function(response) {
            expect(response.data).toEqual([]);
        });

        httpBackend.expectGET(
            URL + "/initialSync?access_token=foobar&limit=15")
            .respond([]);
        httpBackend.flush();
    }));
    
    it('should be able to GET /rooms/$roomid/state', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.roomState(roomId).then(function(response) {
            expect(response.data).toEqual([]);
        });

        httpBackend.expectGET(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/state?access_token=foobar")
            .respond([]);
        httpBackend.flush();
    }));
    
    it('should be able to POST /join', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.joinAlias(roomId).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(
            URL + "/join/" + encodeURIComponent(roomId) + 
            "?access_token=foobar",
            {})
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to POST /rooms/$roomid/join', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.join(roomId).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/join?access_token=foobar",
            {})
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to POST /rooms/$roomid/invite', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var inviteUserId = "@user:example.com";
        matrixService.invite(roomId, inviteUserId).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/invite?access_token=foobar",
            {
                user_id: inviteUserId
            })
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to POST /rooms/$roomid/leave', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.leave(roomId).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/leave?access_token=foobar",
            {})
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to POST /rooms/$roomid/ban', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var userId = "@example:example.com";
        var reason = "Because.";
        matrixService.ban(roomId, userId, reason).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/ban?access_token=foobar",
            {
                user_id: userId,
                reason: reason
            })
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to GET /directory/room/$alias', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var alias = "#test:example.com";
        var roomId = "!wefuhewfuiw:example.com";
        matrixService.resolveRoomAlias(alias).then(function(response) {
            expect(response.data).toEqual({
                room_id: roomId
            });
        });

        httpBackend.expectGET(
            URL + "/directory/room/" + encodeURIComponent(alias) +
                    "?access_token=foobar")
            .respond({
                room_id: roomId
            });
        httpBackend.flush();
    }));
    
    it('should be able to send m.room.name', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var roomId = "!fh38hfwfwef:example.com";
        var name = "Room Name";
        matrixService.setName(roomId, name).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPUT(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/state/m.room.name?access_token=foobar",
            {
                name: name
            })
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to send m.room.topic', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var roomId = "!fh38hfwfwef:example.com";
        var topic = "A room topic can go here.";
        matrixService.setTopic(roomId, topic).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPUT(
            URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/state/m.room.topic?access_token=foobar",
            {
                topic: topic
            })
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to send generic state events without a state key', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var roomId = "!fh38hfwfwef:example.com";
        var eventType = "com.example.events.test";
        var content = {
            testing: "1 2 3"
        };
        matrixService.sendStateEvent(roomId, eventType, content).then(
        function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPUT(
            URL + "/rooms/" + encodeURIComponent(roomId) + "/state/" + 
            encodeURIComponent(eventType) + "?access_token=foobar",
            content)
            .respond({});
        httpBackend.flush();
    }));
    
    // TODO: Skipped since the webclient is purposefully broken so as not to
    // 500 matrix.org
    xit('should be able to send generic state events with a state key', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var roomId = "!fh38hfwfwef:example.com";
        var eventType = "com.example.events.test:special@characters";
        var content = {
            testing: "1 2 3"
        };
        var stateKey = "version:1";
        matrixService.sendStateEvent(roomId, eventType, content, stateKey).then(
        function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPUT(
            URL + "/rooms/" + encodeURIComponent(roomId) + "/state/" + 
            encodeURIComponent(eventType) + "/" + encodeURIComponent(stateKey)+
            "?access_token=foobar",
            content)
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to PUT generic events ', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var roomId = "!fh38hfwfwef:example.com";
        var eventType = "com.example.events.test";
        var txnId = "42";
        var content = {
            testing: "1 2 3"
        };
        matrixService.sendEvent(roomId, eventType, txnId, content).then(
        function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPUT(
            URL + "/rooms/" + encodeURIComponent(roomId) + "/send/" + 
            encodeURIComponent(eventType) + "/" + encodeURIComponent(txnId)+
            "?access_token=foobar",
            content)
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to PUT text messages ', inject(
    function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        var roomId = "!fh38hfwfwef:example.com";
        var body = "ABC 123";
        matrixService.sendTextMessage(roomId, body).then(
        function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPUT(
            new RegExp(URL + "/rooms/" + encodeURIComponent(roomId) + 
            "/send/m.room.message/(.*)" +
            "?access_token=foobar"),
            {
                body: body,
                msgtype: "m.text"
            })
            .respond({});
        httpBackend.flush();
    }));
});
