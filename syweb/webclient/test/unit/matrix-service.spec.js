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

    it('should be able to POST /createRoom with an alias', inject(function(matrixService) {
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
    
    it('should be able to GET /rooms/$roomid/state', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.roomState(roomId).then(function(response) {
            expect(response.data).toEqual([]);
        });

        httpBackend.expectGET(
            URL + "/rooms/" + encodeURIComponent(roomId) + "/state?access_token=foobar")
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
            URL + "/join/" + encodeURIComponent(roomId) + "?access_token=foobar")
            .respond({});
        httpBackend.flush();
    }));
    
    it('should be able to POST /rooms/$roomid/join', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.join(roomId).then(function(response) {
            expect(response.data).toEqual({});
        });

        httpBackend.expectPOST(
            URL + "/rooms/" + encodeURIComponent(roomId) + "/join?access_token=foobar")
            .respond({});
        httpBackend.flush();
    }));
});
