var accountInfo = {};

var eventStreamInfo = {
    from: "END"
};

var roomInfo = [];
var memberInfo = [];
var viewingRoomId;

// ************** Event Streaming **************
var longpollEventStream = function() {
    var url = "http://localhost:8008/_matrix/client/api/v1/events?access_token=$token&from=$from";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$from", eventStreamInfo.from);

    $.getJSON(url, function(data) {
        eventStreamInfo.from = data.end;
        
        var hasNewLatestMessage = false;
        var updatedMemberList = false;
        var i=0;
        var j=0;
        for (i=0; i<data.chunk.length; ++i) {
            if (data.chunk[i].type === "m.room.message") {
                console.log("Got new message: " + JSON.stringify(data.chunk[i]));
                if (viewingRoomId === data.chunk[i].room_id) {
                    addMessage(data.chunk[i]);
                }
                
                for (j=0; j<roomInfo.length; ++j) {
                    if (roomInfo[j].room_id === data.chunk[i].room_id) {
                        roomInfo[j].latest_message = data.chunk[i].content.body;
                        hasNewLatestMessage = true;
                    }
                }
            }
            else if (data.chunk[i].type === "m.room.member") {
                if (viewingRoomId === data.chunk[i].room_id) {
                    console.log("Got new member: " + JSON.stringify(data.chunk[i]));
                    addMessage(data.chunk[i]);
                    for (j=0; j<memberInfo.length; ++j) {
                        if (memberInfo[j].state_key === data.chunk[i].state_key) {
                            memberInfo[j] = data.chunk[i];
                            updatedMemberList = true;
                            break;
                        }
                    }
                    if (!updatedMemberList) {
                        memberInfo.push(data.chunk[i]);  
                        updatedMemberList = true;
                    }
                }
                if (data.chunk[i].state_key === accountInfo.user_id) {
                    getCurrentRoomList(); // update our join/invite list
                }
            }
            else {
                console.log("Discarding: " + JSON.stringify(data.chunk[i]));
            }
        }
        
        if (hasNewLatestMessage) {
           setRooms(roomInfo);
        }
        if (updatedMemberList) {
            $("#members").empty();
            for (i=0; i<memberInfo.length; ++i) { 
                addMember(memberInfo[i]);
            }
        }
        longpollEventStream();
    }).fail(function(err) {
        setTimeout(longpollEventStream, 5000);
    });
};

// ************** Registration and Login **************
var onLoggedIn = function(data) {
    accountInfo = data;
    longpollEventStream();
    getCurrentRoomList();
    $(".roomListDashboard").css({visibility: "visible"});
    $(".roomContents").css({visibility: "visible"});
    $(".signUp").css({display: "none"});
};

$('.login').live('click', function() {
    var user = $("#userLogin").val();
    var password = $("#passwordLogin").val();
    $.ajax({
        url: "http://localhost:8008/_matrix/client/api/v1/login",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({ user: user, password: password, type: "m.login.password" }),
        dataType: "json",
        success: function(data) {
            onLoggedIn(data);
        },
        error: function(err) {
            alert("Unable to login: is the home server running?");  
        }
    }); 
});

$('.register').live('click', function() {
    var user = $("#userReg").val();
    var password = $("#passwordReg").val();
    $.ajax({
        url: "http://localhost:8008/_matrix/client/api/v1/register",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({ user: user, password: password, type: "m.login.password" }),
        dataType: "json",
        success: function(data) {
            onLoggedIn(data);
        },
        error: function(err) {
            var msg = "Is the home server running?";
            var errJson = $.parseJSON(err.responseText);
            if (errJson !== null) {
                msg = errJson.error;   
            }
            alert("Unable to register: "+msg);  
        }
    });
});

// ************** Creating a room ******************
$('.createRoom').live('click', function() {
    var roomAlias = $("#roomAlias").val();
    var data = {};
    if (roomAlias.length > 0) {
        data.room_alias_name = roomAlias;   
    }
    $.ajax({
        url: "http://localhost:8008/_matrix/client/api/v1/createRoom?access_token="+accountInfo.access_token,
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(data),
        dataType: "json",
        success: function(response) {
            $("#roomAlias").val("");
            response.membership = "join"; // you are automatically joined into every room you make.
            response.latest_message = "";
            
            roomInfo.push(response);
            setRooms(roomInfo);
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    }); 
});

// ************** Getting current state **************
var getCurrentRoomList = function() {
    var url = "http://localhost:8008/_matrix/client/api/v1/initialSync?access_token=" + accountInfo.access_token + "&limit=1";
    $.getJSON(url, function(data) {
        var rooms = data.rooms;
        for (var i=0; i<rooms.length; ++i) {
            if ("messages" in rooms[i]) {
                rooms[i].latest_message = rooms[i].messages.chunk[0].content.body;   
            }
        }
        roomInfo = rooms;
        setRooms(roomInfo);  
    }).fail(function(err) {
        alert(JSON.stringify($.parseJSON(err.responseText)));
    });
};

var loadRoomContent = function(roomId) {
    console.log("loadRoomContent " + roomId);
    viewingRoomId = roomId;
    $("#roomName").text("Room: "+roomId);
    $(".sendMessageForm").css({visibility: "visible"});
    getMessages(roomId);
    getMemberList(roomId);
};

var getMessages = function(roomId) {
    $("#messages").empty();
    var url = "http://localhost:8008/_matrix/client/api/v1/rooms/" + 
              encodeURIComponent(roomId) + "/messages?access_token=" + accountInfo.access_token + "&from=END&dir=b&limit=10";
    $.getJSON(url, function(data) {
        for (var i=data.chunk.length-1; i>=0; --i) {
            addMessage(data.chunk[i]);   
        }
    });
};

var getMemberList = function(roomId) {
    $("#members").empty();
    memberInfo = [];
    var url = "http://localhost:8008/_matrix/client/api/v1/rooms/" + 
              encodeURIComponent(roomId) + "/members?access_token=" + accountInfo.access_token;
    $.getJSON(url, function(data) {
        for (var i=0; i<data.chunk.length; ++i) {
            memberInfo.push(data.chunk[i]);
            addMember(data.chunk[i]);   
        }
    });
};

// ************** Sending messages **************
$('.sendMessage').live('click', function() {
    if (viewingRoomId === undefined) {
        alert("There is no room to send a message to!");
        return;
    }
    var body = $("#body").val();
    sendMessage(viewingRoomId, body);
});

var sendMessage = function(roomId, body) {
    var msgId = $.now();
    
    var url = "http://localhost:8008/_matrix/client/api/v1/rooms/$roomid/send/m.room.message?access_token=$token";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$roomid", encodeURIComponent(roomId));
    
    var data = {
        msgtype: "m.text",
        body: body
    };
    
    $.ajax({
        url: url,
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(data),
        dataType: "json",
        success: function(data) {
            $("#body").val("");
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    });
};

// ************** Navigation and DOM manipulation **************
var setRooms = function(roomList) {
    // wipe existing entries
    $("#rooms").find("tr:gt(0)").remove();
    
    var rows = "";
    for (var i=0; i<roomList.length; ++i) {
        row = "<tr>" +
              "<td>"+roomList[i].room_id+"</td>" +
              "<td>"+roomList[i].membership+"</td>" +
              "<td>"+roomList[i].latest_message+"</td>" +
              "</tr>";  
        rows += row;
    }
    
    $("#rooms").append(rows);
    
    $('#rooms').find("tr").click(function(){
        var roomId = $(this).find('td:eq(0)').text();
        var membership = $(this).find('td:eq(1)').text();
        if (membership !== "join") {
            console.log("Joining room " + roomId); 
            var url = "http://localhost:8008/_matrix/client/api/v1/rooms/$roomid/join?access_token=$token";
            url = url.replace("$token", accountInfo.access_token);
            url = url.replace("$roomid", encodeURIComponent(roomId));
            $.ajax({
                url: url,
                type: "POST",
                contentType: "application/json; charset=utf-8",
                data: JSON.stringify({membership: "join"}),
                dataType: "json",
                success: function(data) {
                    loadRoomContent(roomId);
                    getCurrentRoomList();
                },
                error: function(err) {
                    alert(JSON.stringify($.parseJSON(err.responseText)));  
                }
            });
        }
        else {
            loadRoomContent(roomId);
        }
    });
};

var addMessage = function(data) {

    var msg = data.content.body;
    if (data.type === "m.room.member") {
        if (data.content.membership === undefined) {
            return;
        }
        if (data.content.membership === "invite") {
            msg = "<em>invited " + data.state_key + " to the room</em>";
        }
        else if (data.content.membership === "join") {
            msg = "<em>joined the room</em>";
        }
        else if (data.content.membership === "leave") {
            msg = "<em>left the room</em>";
        }
        else if (data.content.membership === "ban") {
            msg = "<em>was banned from the room</em>";
        }
    }
    if (msg === undefined) {
        return;
    }

    var row = "<tr>" +
              "<td>"+data.user_id+"</td>" +
              "<td>"+msg+"</td>" +
              "</tr>"; 
    $("#messages").append(row);
};

var addMember = function(data) {
    var row = "<tr>" +
              "<td>"+data.state_key+"</td>" +
              "<td>"+data.content.membership+"</td>" +
              "</tr>"; 
    $("#members").append(row);
};

