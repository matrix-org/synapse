describe("RegisterController ", function() {
    var rootScope, scope, ctrl, $q, $timeout;
    var userId = "@foo:bar";
    var displayName = "Foo";
    var avatarUrl = "avatar.url";
    
    window.webClientConfig = {
        useCapatcha: false
    };
    
    // test vars
    var testRegisterData, testFailRegisterData;
    
    
    // mock services
    var matrixService = {
        config: function() {
            return {
                user_id: userId
            }
        },
        setConfig: function(){},
        register: function(mxid, password, threepidCreds, useCaptcha) {
            var d = $q.defer();
            if (testFailRegisterData) {
                d.reject({
                    data: testFailRegisterData
                });
            }
            else {
                d.resolve({
                    data: testRegisterData
                });
            }
            return d.promise;
        }
    };
    
    var eventStreamService = {};
    
    beforeEach(function() {
        module('matrixWebClient');
        
        // reset test vars
        testRegisterData = undefined;
        testFailRegisterData = undefined;
    });

    beforeEach(inject(function($rootScope, $injector, $location, $controller, _$q_, _$timeout_) {
            $q = _$q_;
            $timeout = _$timeout_;
            scope = $rootScope.$new();
            rootScope = $rootScope;
            routeParams = {
                user_matrix_id: userId
            };
            ctrl = $controller('RegisterController', {
                '$scope': scope,
                '$rootScope': $rootScope, 
                '$location': $location,
                'matrixService': matrixService,
                'eventStreamService': eventStreamService
            });
        })
    );

    // SYWEB-109
    it('should display an error if the HS rejects the username on registration', function() {
        var prevFeedback = angular.copy(scope.feedback);
    
        testFailRegisterData = {
            errcode: "M_UNKNOWN",
            error: "I am rejecting you."
        };
    
        scope.account.pwd1 = "password";
        scope.account.pwd2 = "password";
        scope.account.desired_user_id = "bob";
        scope.register();
        rootScope.$digest();
        
        expect(scope.feedback).not.toEqual(prevFeedback);
    });
});
