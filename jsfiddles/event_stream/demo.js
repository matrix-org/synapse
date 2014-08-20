var accountInfo = {};

var eventStreamInfo = {
    from: "END"
};

var roomInfo = [];

var longpollEventStream = function() {
    var url = "http://localhost:8080/matrix/client/api/v1/events?access_token=$token&from=$from";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$from", eventStreamInfo.from);
    
    $.getJSON(url, function(data) {
        eventStreamInfo.from = data.end;
        
        var hasNewLatestMessage = false;
        for (var i=0; i<data.chunk.length; ++i) {
            if (data.chunk[i].type === "m.room.message") {
                for (var j=0; j<roomInfo.length; ++j) {
                    if (roomInfo[j].room_id === data.chunk[i].room_id) {
                        roomInfo[j].latest_message = data.chunk[i].content.body;
                        hasNewLatestMessage = true;
                    }
                }
            }
        }
        
        if (hasNewLatestMessage) {
           setRooms(roomInfo);
        }
        $("#streamErrorText").text("");
        longpollEventStream();
    }).fail(function(err) {
        $("#streamErrorText").text("Event stream error: "+JSON.stringify($.parseJSON(err.responseText)));
        setTimeout(longpollEventStream, 5000);
    });
};

var showLoggedIn = function(data) {
    accountInfo = data;
    longpollEventStream();
    getCurrentRoomList();
    $(".loggedin").css({visibility: "visible"});
};

$('.login').live('click', function() {
    var user = $("#userLogin").val();
    var password = $("#passwordLogin").val();
    $.ajax({
        url: "http://localhost:8080/matrix/client/api/v1/login",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({ user: user, password: password, type: "m.login.password" }),
        dataType: "json",
        success: function(data) {
            $("#rooms").find("tr:gt(0)").remove();
            showLoggedIn(data);
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    }); 
});

var getCurrentRoomList = function() {
    $("#roomId").val("");
    var url = "http://localhost:8080/matrix/client/api/v1/im/sync?access_token=" + accountInfo.access_token + "&from=END&to=START&limit=1";
    $.getJSON(url, function(data) {
        for (var i=0; i<data.length; ++i) {
            if ("messages" in data[i]) {
                data[i].latest_message = data[i].messages.chunk[0].content.body;   
            }
        }
        roomInfo = data;
        setRooms(roomInfo);  
    }).fail(function(err) {
        alert(JSON.stringify($.parseJSON(err.responseText)));
    });
};

$('.sendMessage').live('click', function() {
    if (roomInfo.length === 0) {
        alert("There is no room to send a message to!");
        return;
    }
    
    var index = Math.floor(Math.random() * roomInfo.length);
    
    sendMessage(roomInfo[index].room_id);
});

var sendMessage = function(roomId) {
    var body = "jsfiddle message @" + $.now();
    var msgId = $.now();
    
    if (roomId.length === 0) {
        return;
    }
    
    var url = "http://localhost:8080/matrix/client/api/v1/rooms/$roomid/messages/$user/$msgid?access_token=$token";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$roomid", encodeURIComponent(roomId));
    url = url.replace("$user", encodeURIComponent(accountInfo.user_id));
    url = url.replace("$msgid", msgId);
    
    var data = {
        msgtype: "m.text",
        body: body
    };
    
    $.ajax({
        url: url,
        type: "PUT",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(data),
        dataType: "json",
        success: function(data) {
            $("#messageBody").val("");
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    }); 
};

var setRooms = function(roomList) {
    // wipe existing entries
    $("#rooms").find("tr:gt(0)").remove();
    
    var rows = "";
    for (var i=0; i<roomList.length; ++i) {
        row = "<tr>" +
            "<td>"+roomList[i].room_id+"</td>" +
            "<td>"+roomList[i].latest_message+"</td>" +
            "</tr>";  
        rows += row;
    }
    
    $("#rooms").append(rows);
};

