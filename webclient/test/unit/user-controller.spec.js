describe("UserCtrl", function() {
    var scope, ctrl, matrixService, routeParams, $q, $timeout;
    var userId = "@foo:bar";
    var displayName = "Foo";
    var avatarUrl = "avatar.url";
    
    beforeEach(module('matrixWebClient'));

    beforeEach(function() {

        inject(function($rootScope, $injector, $controller, _$q_, _$timeout_) {
            $q = _$q_;
            $timeout = _$timeout_;

            matrixService = {
                config: function() {
                    return {
                        user_id: userId
                    };
                },

                getDisplayName: function(uid) {
                    var d = $q.defer();
                    // FIXME: everything goes into fire here
                    d.resolve({
                        data: {
                            displayname: displayName
                        }
                    });
                    return d;
                },

                getProfilePictureUrl: function(uid) {
                    var d = $q.defer();
                    d.resolve({
                        data: {
                            avatar_url: avatarUrl
                        }
                    });
                    return d;
                }
            };
            scope = $rootScope.$new();
            routeParams = {
                user_matrix_id: userId
            };
            ctrl = $controller('UserController', {
                '$scope': scope, 
                '$routeParams': routeParams, 
                'matrixService': matrixService
            });
            console.log("end inject");
        });
    });

    it('should display your user id', function() {
        expect(scope.user_id).toEqual(userId);
    });
});
