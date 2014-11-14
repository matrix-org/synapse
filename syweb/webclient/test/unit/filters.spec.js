describe('mRoomName filter', function() {
    var filter, mRoomName, mUserDisplayName;
    
    var roomId = "!weufhewifu:matrix.org";
    
    // test state values (f.e. test)
    var testUserId, testAlias, testDisplayName, testOtherDisplayName, testRoomState;
    
    // mocked services which return the test values above.
    var matrixService = {
        config: function() {
            return {
                user_id: testUserId
            };
        }
    };
    
    var modelService = {
        getRoom: function(room_id) {
            return {
                current_room_state: testRoomState
            };
        },
        
        getRoomIdToAliasMapping: function(room_id) {
            return testAlias;
        },
    };
    
    beforeEach(function() {
        // inject mocked dependencies
        module(function ($provide) {
            $provide.value('matrixService', matrixService);
            $provide.value('modelService', modelService);
        });
        
        module('matrixFilter');
        
        // angular resolves dependencies with the same name via a 'last wins'
        // rule, hence we need to have this mock filter impl AFTER module('matrixFilter')
        // so it clobbers the actual mUserDisplayName implementation.
        module(function ($filterProvider) {
            // provide a fake filter
            $filterProvider.register('mUserDisplayName', function() {
                return function(user_id, room_id) {
                    if (user_id === testUserId) {
                        return testDisplayName;
                    }
                    return testOtherDisplayName;
                };
            });
        });
    });
    
    
    beforeEach(inject(function($filter) {
        filter = $filter;
        mRoomName = filter("mRoomName");
        
        // purge the previous test values
        testUserId = undefined;
        testAlias = undefined;
        testDisplayName = undefined;
        testOtherDisplayName = undefined;
        
        // mock up a stub room state
        testRoomState = {
            s:{}, // internal; stores the state events
            state: function(type, key) {
                // accessor used by filter
                return key ? this.s[type+key] : this.s[type];
            },
            members: {}, // struct used by filter
            
            // test helper methods
            setJoinRule: function(rule) {
                this.s["m.room.join_rules"] = {
                    content: {
                        join_rule: rule
                    }
                };
            },
            setRoomName: function(name) {
                this.s["m.room.name"] = {
                    content: {
                        name: name
                    }
                };
            },
            setMember: function(user_id, membership, inviter_user_id) {
                if (!inviter_user_id) {
                    inviter_user_id = user_id;
                }
                this.s["m.room.member" + user_id] = {
                    event: {
                        content: {
                            membership: membership
                        },
                        state_key: user_id,
                        user_id: inviter_user_id 
                    }
                };
                this.members[user_id] = this.s["m.room.member" + user_id];
            }
        };
    }));
    
    /**** ROOM NAME ****/
    
    it("should show the room name if one exists for private (invite join_rules) rooms.", function() {
        var roomName = "The Room Name";
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("invite");
        testRoomState.setRoomName(roomName);
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(roomName);
    });
    
    it("should show the room name if one exists for public (public join_rules) rooms.", function() {
        var roomName = "The Room Name";
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("public");
        testRoomState.setRoomName(roomName);
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(roomName);
    });
    
    /**** ROOM ALIAS ****/
    
    it("should show the room alias if one exists for private (invite join_rules) rooms if a room name doesn't exist.", function() {
        testAlias = "#thealias:matrix.org";
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("invite");
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(testAlias);
    });
    
    it("should show the room alias if one exists for public (public join_rules) rooms if a room name doesn't exist.", function() {
        testAlias = "#thealias:matrix.org";
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("public");
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(testAlias);
    });
    
    /**** ROOM ID ****/
    
    it("should show the room ID for public (public join_rules) rooms if a room name and alias don't exist.", function() {
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("public");
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(roomId);
    });
    
    it("should show the room ID for private (invite join_rules) rooms if a room name and alias don't exist and there are >2 members.", function() {
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("public");
        testRoomState.setMember(testUserId, "join");
        testRoomState.setMember("@alice:matrix.org", "join");
        testRoomState.setMember("@bob:matrix.org", "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(roomId);
    });
    
    /**** SELF-CHAT ****/
    
    it("should show your display name for private (invite join_rules) rooms if a room name and alias don't exist and it is a self-chat.", function() {
        testUserId = "@me:matrix.org";
        testDisplayName = "Me";
        testRoomState.setJoinRule("private");
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(testDisplayName);
    });
    
    it("should show your user ID for private (invite join_rules) rooms if a room name and alias don't exist and it is a self-chat and they don't have a display name set.", function() {
        testUserId = "@me:matrix.org";
        testRoomState.setJoinRule("private");
        testRoomState.setMember(testUserId, "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(testUserId);
    });
    
    /**** ONE-TO-ONE CHAT ****/
    
    it("should show the other user's display name for private (invite join_rules) rooms if a room name and alias don't exist and it is a 1:1-chat.", function() {
        testUserId = "@me:matrix.org";
        otherUserId = "@alice:matrix.org";
        testOtherDisplayName = "Alice";
        testRoomState.setJoinRule("private");
        testRoomState.setMember(testUserId, "join");
        testRoomState.setMember("@alice:matrix.org", "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(testOtherDisplayName);
    });
    
    it("should show the other user's ID for private (invite join_rules) rooms if a room name and alias don't exist and it is a 1:1-chat and they don't have a display name set.", function() {
        testUserId = "@me:matrix.org";
        otherUserId = "@alice:matrix.org";
        testRoomState.setJoinRule("private");
        testRoomState.setMember(testUserId, "join");
        testRoomState.setMember("@alice:matrix.org", "join");
        var output = mRoomName(roomId);
        expect(output).toEqual(otherUserId);
    });
    
    /**** INVITED TO ROOM ****/
    
    it("should show the other user's display name for private (invite join_rules) rooms if you are invited to it.", function() {
        testUserId = "@me:matrix.org";
        testDisplayName = "Me";
        otherUserId = "@alice:matrix.org";
        testOtherDisplayName = "Alice";
        testRoomState.setJoinRule("private");
        testRoomState.setMember(testUserId, "join");
        testRoomState.setMember(otherUserId, "join");
        testRoomState.setMember(testUserId, "invite");
        var output = mRoomName(roomId);
        expect(output).toEqual(testOtherDisplayName);
    });
    
    it("should show the other user's ID for private (invite join_rules) rooms if you are invited to it and the inviter doesn't have a display name.", function() {
        testUserId = "@me:matrix.org";
        testDisplayName = "Me";
        otherUserId = "@alice:matrix.org";
        testRoomState.setJoinRule("private");
        testRoomState.setMember(testUserId, "join");
        testRoomState.setMember(otherUserId, "join");
        testRoomState.setMember(testUserId, "invite");
        var output = mRoomName(roomId);
        expect(output).toEqual(otherUserId);
    });
});

describe('duration filter', function() {
    var filter, durationFilter;
    
    beforeEach(module('matrixWebClient'));
    beforeEach(inject(function($filter) {
        filter = $filter;
        durationFilter = filter("duration");
    }));
    
    it("should represent 15000 ms as '15s'", function() {
        var output = durationFilter(15000);
        expect(output).toEqual("15s");
    });
    
    it("should represent 60000 ms as '1m'", function() {
        var output = durationFilter(60000);
        expect(output).toEqual("1m");
    });
    
    it("should represent 65000 ms as '1m'", function() {
        var output = durationFilter(65000);
        expect(output).toEqual("1m");
    });
    
    it("should represent 10 ms as '0s'", function() {
        var output = durationFilter(10);
        expect(output).toEqual("0s");
    });
    
    it("should represent 4m as '4m'", function() {
        var output = durationFilter(1000*60*4);
        expect(output).toEqual("4m");
    });
    
    it("should represent 4m30s as '4m'", function() {
        var output = durationFilter(1000*60*4 + 1000*30);
        expect(output).toEqual("4m");
    });
    
    it("should represent 2h as '2h'", function() {
        var output = durationFilter(1000*60*60*2);
        expect(output).toEqual("2h");
    });
    
    it("should represent 2h35m as '2h'", function() {
        var output = durationFilter(1000*60*60*2 + 1000*60*35);
        expect(output).toEqual("2h");
    });
});

describe('orderMembersList filter', function() {
    var filter, orderMembersList;
    
    beforeEach(module('matrixWebClient'));
    beforeEach(inject(function($filter) {
        filter = $filter;
        orderMembersList = filter("orderMembersList");
    }));
    
    it("should sort a single entry", function() {
        var output = orderMembersList({
            "@a:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 50
                        }
                    },
                    last_updated: 1415266943964
                }
            }
        });
        expect(output).toEqual([{
                id: "@a:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 50
                        }
                    },
                    last_updated: 1415266943964
                }
        }]);
    });
    
    it("should sort by taking last_active_ago into account", function() {
        var output = orderMembersList({
            "@a:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            "@b:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 50
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            "@c:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 99999
                        }
                    },
                    last_updated: 1415266943964
                }
            }
        });
        expect(output).toEqual([
            {
                id: "@b:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 50
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@a:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@c:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 99999
                        }
                    },
                    last_updated: 1415266943964
                }
            },
        ]);
    });
    
    it("should sort by taking last_updated into account", function() {
        var output = orderMembersList({
            "@a:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            "@b:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266900000
                }
            },
            "@c:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943000
                }
            }
        });
        expect(output).toEqual([
            {
                id: "@a:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@c:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943000
                }
            },
            {
                id: "@b:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266900000
                }
            },
        ]);
    });
    
    it("should sort by taking last_updated and last_active_ago into account", 
    function() {
        var output = orderMembersList({
            "@a:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943000
                }
            },
            "@b:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 100000
                        }
                    },
                    last_updated: 1415266943900
                }
            },
            "@c:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            }
        });
        expect(output).toEqual([
            {
                id: "@c:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@a:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943000
                }
            },
            {
                id: "@b:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 100000
                        }
                    },
                    last_updated: 1415266943900
                }
            },
        ]);
    });
    
    // SYWEB-26 comment
    it("should sort members who do not have last_active_ago value at the end of the list", 
    function() {
        // single undefined entry
        var output = orderMembersList({
            "@a:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            "@b:example.com": {
                user: {
                    event: {
                        content: {
                            last_active_ago: 100000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            "@c:example.com": {
                user: {
                    last_updated: 1415266943964
                }
            }
        });
        expect(output).toEqual([
            {
                id: "@a:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 1000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@b:example.com",
                user: {
                    event: {
                        content: {
                            last_active_ago: 100000
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@c:example.com",
                user: {
                    last_updated: 1415266943964
                }
            },
        ]);
    });
    
    it("should sort multiple members who do not have last_active_ago according to presence", 
    function() {
        // single undefined entry
        var output = orderMembersList({
            "@a:example.com": {
                user: {
                    event: {
                        content: {
                            presence: "unavailable",
                            last_active_ago: undefined
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            "@b:example.com": {
                user: {
                    event: {
                        content: {
                            presence: "online",
                            last_active_ago: undefined
                        }
                    },
                    last_updated: 1415266943964,
                }
            },
            "@c:example.com": {
                user: {
                    event: {
                        content: {
                            presence: "offline",
                            last_active_ago: undefined
                        }
                    },
                    last_updated: 1415266943964
                }
            }
        });
        expect(output).toEqual([
            {
                id: "@b:example.com",
                user: {
                    event: {
                        content: {
                            presence: "online",
                            last_active_ago: undefined
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@a:example.com",
                user: {
                    event: {
                        content: {
                            presence: "unavailable",
                            last_active_ago: undefined
                        }
                    },
                    last_updated: 1415266943964
                }
            },
            {
                id: "@c:example.com",
                user: {
                    event: {
                        content: {
                            presence: "offline",
                            last_active_ago: undefined
                        }
                    },
                    last_updated: 1415266943964
                }
            },
        ]);
    });
});
describe('mUserDisplayName filter', function() {
    var filter, mUserDisplayName;
    
    var roomId = "!weufhewifu:matrix.org";
    
    // test state values (f.e. test)
    var testUser_displayname, testUser_user_id;
    var testSelf_displayname, testSelf_user_id;
    var testRoomState;
    
    // mocked services which return the test values above.
    var matrixService = {
        config: function() {
            return {
                user_id: testSelf_user_id
            };
        }
    };
    
    var modelService = {
        getRoom: function(room_id) {
            return {
                current_room_state: testRoomState
            };
        },
        
        getUser: function(user_id) {
            return {
                event: {
                    content: {
                        displayname: testUser_displayname
                    },
                    event_id: "wfiuhwf@matrix.org",
                    user_id: testUser_user_id
                }
            };
        },
        
        getMember: function(room_id, user_id) {
            return testRoomState.members[user_id];
        }
    };
    
    beforeEach(function() {
        // inject mocked dependencies
        module(function ($provide) {
            $provide.value('matrixService', matrixService);
            $provide.value('modelService', modelService);
        });
        
        module('matrixFilter');
    });
    
    
    beforeEach(inject(function($filter) {
        filter = $filter;
        mUserDisplayName = filter("mUserDisplayName");
        
        // purge the previous test values
        testSelf_displayname = "Me"; 
        testSelf_user_id = "@me:matrix.org";
        testUser_displayname = undefined; 
        testUser_user_id = undefined;
        
        // mock up a stub room state
        testRoomState = {
            s:{}, // internal; stores the state events
            state: function(type, key) {
                // accessor used by filter
                return key ? this.s[type+key] : this.s[type];
            },
            members: {}, // struct used by filter
            
            // test helper methods
            setMember: function(user_id, displayname, membership, inviter_user_id) {
                if (!inviter_user_id) {
                    inviter_user_id = user_id;
                }
                if (!membership) {
                    membership = "join";
                }
                this.s["m.room.member" + user_id] = {
                    event: {
                        content: {
                            displayname: displayname,
                            membership: membership
                        },
                        state_key: user_id,
                        user_id: inviter_user_id 
                    }
                };
                this.members[user_id] = this.s["m.room.member" + user_id];
            }
        };
    }));
    
    it("should show the display name of a user in a room if they have set one.", function() {
        testUser_displayname = "Tom Scott";
        testUser_user_id = "@tymnhk:matrix.org";
        testRoomState.setMember(testUser_user_id, testUser_displayname);
        testRoomState.setMember(testSelf_user_id, testSelf_displayname);
        var output = mUserDisplayName(testUser_user_id, roomId);
        expect(output).toEqual(testUser_displayname);
    });
    
    it("should show the user_id of a user in a room if they have no display name.", function() {
        testUser_user_id = "@mike:matrix.org";
        testRoomState.setMember(testUser_user_id, testUser_displayname);
        testRoomState.setMember(testSelf_user_id, testSelf_displayname);
        var output = mUserDisplayName(testUser_user_id, roomId);
        expect(output).toEqual(testUser_user_id);
    });
    
    it("should still show the displayname of a user in a room if they are not a member of the room but there exists a User entry for them.", function() {
        testUser_user_id = "@alice:matrix.org";
        testUser_displayname = "Alice M";
        testRoomState.setMember(testSelf_user_id, testSelf_displayname);
        var output = mUserDisplayName(testUser_user_id, roomId);
        expect(output).toEqual(testUser_displayname);
    });
    
    it("should disambiguate users with the same displayname with their user id.", function() {
        testUser_displayname = "Reimu";
        testSelf_displayname = "Reimu";
        testUser_user_id = "@reimu:matrix.org";
        testSelf_user_id = "@xreimux:matrix.org";
        testRoomState.setMember(testUser_user_id, testUser_displayname);
        testRoomState.setMember(testSelf_user_id, testSelf_displayname);
        var output = mUserDisplayName(testUser_user_id, roomId);
        expect(output).toEqual(testUser_displayname + " (" + testUser_user_id + ")");
    });
    
    it("should wrap user IDs after the : if the wrap flag is set.", function() {
        testUser_user_id = "@mike:matrix.org";
        testRoomState.setMember(testUser_user_id, testUser_displayname);
        testRoomState.setMember(testSelf_user_id, testSelf_displayname);
        var output = mUserDisplayName(testUser_user_id, roomId, true);
        expect(output).toEqual("@mike :matrix.org");
    });
});

