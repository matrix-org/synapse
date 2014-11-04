// Karma configuration
// Generated on Thu Sep 18 2014 14:25:57 GMT+0100 (BST)

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',


    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['jasmine'],


    // list of files / patterns to load in the browser
    // XXX: Order is important, and doing /js/angular* makes the tests not run :/
    files: [
      '../js/jquery*',
      '../js/angular.js',
      '../js/angular-mocks.js',
      '../js/angular-route.js',
      '../js/angular-animate.js',
      '../js/angular-sanitize.js',
      '../js/ng-infinite-scroll-matrix.js',
      '../js/ui-bootstrap*',
      '../js/elastic.js',  
      '../login/**/*.*',
      '../room/**/*.*',
      '../components/**/*.*',
      '../user/**/*.*',
      '../home/**/*.*',
      '../recents/**/*.*',
      '../settings/**/*.*',
      '../app.js',
      '../app*',
      './unit/**/*.js'
    ],

    plugins: [
        'karma-*',
    ],


    // list of files to exclude
    exclude: [
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
    },


    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['progress', 'junit'],
    junitReporter: {
        outputFile: 'test-results.xml',
        suite: ''
    },

    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_DEBUG,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['PhantomJS'],


    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: true
  });
};
