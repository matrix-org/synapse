var env = require("./environment-protractor.js");
exports.config = {
    seleniumAddress: env.seleniumAddress,
    specs: ['e2e/*.spec.js'],
    onPrepare: function() {
        browser.driver.get(env.baseUrl);
        browser.driver.findElement(by.id("user_id")).sendKeys(env.username);
        browser.driver.findElement(by.id("password")).sendKeys(env.password);
        browser.driver.findElement(by.id("login")).click();

        // wait till the login is done, detect via url change
        browser.driver.wait(function() {
            return browser.driver.getCurrentUrl().then(function(url) {
                return !(/login/.test(url))
            });
        });
    }
}
