describe("user page", function() {
    it("should have a title", function() {
        browser.get("http://matrix.org/alpha/#/login");
        expect(browser.getTitle()).toEqual("[matrix]");
    });
});
