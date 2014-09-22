var env = require("./environment-protractor.js");

exports.config = {
  seleniumAddress: env.seleniumAddress,
  specs: ['e2e/*.spec.js']
}
