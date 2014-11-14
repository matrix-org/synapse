describe('NotificationService', function() {

    var userId = "@ali:matrix.org";
    var displayName = "Alice M";
    var bingWords = ["coffee","foo(.*)bar"]; // literal and wildcard

    beforeEach(function() {
        module('notificationService');
    });
    
    // User IDs
    
    it('should bing on a user ID.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "Hello @ali:matrix.org, how are you?")).toEqual(true);
    }));
    
    it('should bing on a partial user ID.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "Hello @ali, how are you?")).toEqual(true);
    }));
    
    it('should bing on a case-insensitive user ID.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "Hello @AlI:matrix.org, how are you?")).toEqual(true);
    }));
    
    // Display names
    
    it('should bing on a display name.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "Hello Alice M, how are you?")).toEqual(true);
    }));
    
    it('should bing on a case-insensitive display name.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "Hello ALICE M, how are you?")).toEqual(true);
    }));
    
    // Bing words
    
    it('should bing on a bing word.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "I really like coffee")).toEqual(true);
    }));
    
    it('should bing on case-insensitive bing words.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "Coffee is great")).toEqual(true);
    }));
    
    it('should bing on wildcard (.*) bing words.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, "It was foomahbar I think.")).toEqual(true);
    }));
    
    // invalid
    
    it('should gracefully handle bad input.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, displayName, 
        bingWords, { "foo": "bar" })).toEqual(false);
    }));
    
    it('should gracefully handle just a user ID.', inject(
    function(notificationService) {
        expect(notificationService.containsBingWord(userId, undefined, 
        undefined, "Hello @ali:matrix.org, how are you?")).toEqual(true);
    }));
});
