var accountInfo = {};

var showLoggedIn = function(data) {
    accountInfo = data;
    getCurrentRoomList();
    $(".loggedin").css({visibility: "visible"});
    $("#membership").change(function() {
    if ($("#membership").val() === "invite") {
        $("#targetUser").css({visibility: "visible"});
    }
    else {
        $("#targetUser").css({visibility: "hidden"});
    }
});
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
            $("#rooms").find("tr:gt(0)").remove();
            showLoggedIn(data);
        },
        error: function(err) {
            var errMsg = "To try this, you need a home server running!";
            var errJson = $.parseJSON(err.responseText);
            if (errJson) {
                errMsg = JSON.stringify(errJson);   
            }
            alert(errMsg); 
        }
    }); 
});

var getCurrentRoomList = function() {
    $("#roomId").val("");
    // wipe the table and reload it. Using the event stream would be the best
    // solution but that is out of scope of this fiddle.
    $("#rooms").find("tr:gt(0)").remove();
    
    var url = "http://localhost:8008/_matrix/client/api/v1/initialSync?access_token=" + accountInfo.access_token + "&limit=1";
    $.getJSON(url, function(data) {
        var rooms = data.rooms;
        for (var i=0; i<rooms.length; ++i) {
            addRoom(rooms[i]);   
        }
    }).fail(function(err) {
        alert(JSON.stringify($.parseJSON(err.responseText)));
    });
};

$('.createRoom').live('click', function() {
    var data = {};
    $.ajax({
        url: "http://localhost:8008/_matrix/client/api/v1/createRoom?access_token="+accountInfo.access_token,
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(data),
        dataType: "json",
        success: function(data) {
            data.membership = "join"; // you are automatically joined into every room you make.
            data.latest_message = "";
            addRoom(data);
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    }); 
});

var addRoom = function(data) {
    row = "<tr>" +
        "<td>"+data.room_id+"</td>" +
        "<td>"+data.membership+"</td>" +
        "<td>"+data.room_alias+"</td>" +
        "</tr>";
    $("#rooms").append(row);
};

$('.changeMembership').live('click', function() {
    var roomId = $("#roomId").val();
    var member = $("#targetUser").val();
    var membership = $("#membership").val();
    
    if (roomId.length === 0) {
        return;
    }
    
    var url = "http://localhost:8008/_matrix/client/api/v1/rooms/$roomid/$membership?access_token=$token";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$roomid", encodeURIComponent(roomId));
    url = url.replace("$membership", membership);
    
    var data = {};
    
    if (membership === "invite") {
        data = {
            user_id: member
        };
    }

    $.ajax({
        url: url,
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(data),
        dataType: "json",
        success: function(data) {
            getCurrentRoomList();
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    }); 
});

$('.joinAlias').live('click', function() {
    var roomAlias = $("#roomAlias").val();
    var url = "http://localhost:8008/_matrix/client/api/v1/join/$roomalias?access_token=$token";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$roomalias", encodeURIComponent(roomAlias));
    $.ajax({
        url: url,
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({}),
        dataType: "json",
        success: function(data) {
            getCurrentRoomList();
        },
        error: function(err) {
            alert(JSON.stringify($.parseJSON(err.responseText)));  
        }
    }); 
});
