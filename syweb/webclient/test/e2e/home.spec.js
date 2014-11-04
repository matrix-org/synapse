var env = require("../environment-protractor.js");

describe("home page", function() {

    beforeEach(function() {
        ptor = protractor.getInstance();
        // FIXME we use longpoll on the event stream, and I can't get $interval
        // playing nicely with it. Patches welcome to fix this.
        ptor.ignoreSynchronization = true;
    }); 

    it("should have a title", function() {
        browser.get(env.baseUrl);
        expect(browser.getTitle()).toEqual("[matrix]");
    });
});
