describe('RecentsService', function() {
    var scope;
    var MSG_EVENT = "__test__";
    
    var testEventContainsBingWord, testIsLive, testEvent;
    
    var eventHandlerService = {
        MSG_EVENT: MSG_EVENT,
        eventContainsBingWord: function(event) {
            return testEventContainsBingWord;
        }
    };

    // setup the service and mocked dependencies
    beforeEach(function() {
        
        // set default mock values
        testEventContainsBingWord = false;
        testIsLive = true;
        testEvent = {
            content: {
                body: "Hello world",
                msgtype: "m.text"
            },
            user_id: "@alfred:localhost",
            room_id: "!fl1bb13:localhost",
            event_id: "fwuegfw@localhost"
        }
        
        // mocked dependencies
        module(function ($provide) {
          $provide.value('eventHandlerService', eventHandlerService);
        });
        
        // tested service
        module('recentsService');
    });
    
    beforeEach(inject(function($rootScope) {
        scope = $rootScope;
    }));

    it('should start with no unread messages.', inject(
    function(recentsService) {
        expect(recentsService.getUnreadMessages()).toEqual({});
        expect(recentsService.getUnreadBingMessages()).toEqual({});
    }));
    
    it('should NOT add an unread message to the room currently selected.', inject(
    function(recentsService) {
        recentsService.setSelectedRoomId(testEvent.room_id);
        scope.$broadcast(MSG_EVENT, testEvent, testIsLive);
        expect(recentsService.getUnreadMessages()).toEqual({});
        expect(recentsService.getUnreadBingMessages()).toEqual({});
    }));
    
    it('should add an unread message to the room NOT currently selected.', inject(
    function(recentsService) {
        recentsService.setSelectedRoomId("!someotherroomid:localhost");
        scope.$broadcast(MSG_EVENT, testEvent, testIsLive);
        
        var unread = {};
        unread[testEvent.room_id] = 1;
        expect(recentsService.getUnreadMessages()).toEqual(unread);
    }));
    
    it('should add an unread message and an unread bing message if a message contains a bing word.', inject(
    function(recentsService) {
        recentsService.setSelectedRoomId("!someotherroomid:localhost");
        testEventContainsBingWord = true;
        scope.$broadcast(MSG_EVENT, testEvent, testIsLive);
        
        var unread = {};
        unread[testEvent.room_id] = 1;
        expect(recentsService.getUnreadMessages()).toEqual(unread);
        
        var bing = {};
        bing[testEvent.room_id] = testEvent;
        expect(recentsService.getUnreadBingMessages()).toEqual(bing);
    }));
    
    it('should clear both unread and unread bing messages when markAsRead is called.', inject(
    function(recentsService) {
        recentsService.setSelectedRoomId("!someotherroomid:localhost");
        testEventContainsBingWord = true;
        scope.$broadcast(MSG_EVENT, testEvent, testIsLive);
        
        var unread = {};
        unread[testEvent.room_id] = 1;
        expect(recentsService.getUnreadMessages()).toEqual(unread);
        
        var bing = {};
        bing[testEvent.room_id] = testEvent;
        expect(recentsService.getUnreadBingMessages()).toEqual(bing);
        
        recentsService.markAsRead(testEvent.room_id);
        
        unread[testEvent.room_id] = 0;
        expect(recentsService.getUnreadMessages()).toEqual(unread);
        expect(recentsService.getUnreadBingMessages()).toEqual({});
    }));
    
    it('should not add messages as unread if they are not live.', inject(
    function(recentsService) {
        testIsLive = false;
        
        recentsService.setSelectedRoomId("!someotherroomid:localhost");
        testEventContainsBingWord = true;
        scope.$broadcast(MSG_EVENT, testEvent, testIsLive);
    
        expect(recentsService.getUnreadMessages()).toEqual({});
        expect(recentsService.getUnreadBingMessages()).toEqual({});
    }));
});
