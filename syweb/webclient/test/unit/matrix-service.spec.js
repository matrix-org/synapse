describe('MatrixService', function() {
    var scope, httpBackend, createController;
    var BASE = "http://example.com";
    var PREFIX = "/_matrix/client/api/v1";
    var URL = BASE + PREFIX;
    var roomId = "!wejigf387t34:matrix.org";
    
    beforeEach(module('matrixService'));

    beforeEach(inject(function($rootScope, $httpBackend, $controller) {
        httpBackend = $httpBackend;
        scope = $rootScope;
    }));

    afterEach(function() {
        httpBackend.verifyNoOutstandingExpectation();
        httpBackend.verifyNoOutstandingRequest();
    });

    it('should be able to GET /rooms/$roomid/state', inject(function(matrixService) {
        matrixService.setConfig({
            access_token: "foobar",
            homeserver: "http://example.com"
        });
        matrixService.roomState(roomId).then(function(response) {
            expect(response.data).toEqual([]);
        });

        httpBackend.expect('GET',
            URL + "/rooms/" + roomId + "/state?access_token=foobar")
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

        httpBackend.expect('POST',
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

        httpBackend.expect('POST',
            URL + "/rooms/" + encodeURIComponent(roomId) + "/join?access_token=foobar")
            .respond({});
        httpBackend.flush();
    }));
});
