var env = require("./environment-protractor.js");
exports.config = {
    seleniumAddress: env.seleniumAddress,
    specs: ['e2e/*.spec.js'],
    onPrepare: function() {
        browser.driver.get(env.loginUrl);
        browser.driver.findElement(by.id("user_id")).sendKeys(env.username);
        browser.driver.findElement(by.id("password")).sendKeys(env.password);
        browser.driver.findElement(by.id("login")).click();
    }
}
