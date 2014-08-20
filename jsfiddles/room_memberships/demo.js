var accountInfo = {};

var showLoggedIn = function(data) {
    accountInfo = data;
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
    // wipe the table and reload it. Using the event stream would be the best
    // solution but that is out of scope of this fiddle.
    $("#rooms").find("tr:gt(0)").remove();
    
    var url = "http://localhost:8080/matrix/client/api/v1/im/sync?access_token=" + accountInfo.access_token + "&from=END&to=START&limit=1";
    $.getJSON(url, function(data) {
        for (var i=0; i<data.length; ++i) {
            addRoom(data[i]);   
        }
    }).fail(function(err) {
        alert(JSON.stringify($.parseJSON(err.responseText)));
    });
};

$('.createRoom').live('click', function() {
    var data = {};
    $.ajax({
        url: "http://localhost:8080/matrix/client/api/v1/rooms?access_token="+accountInfo.access_token,
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
    
    var url = "http://localhost:8080/matrix/client/api/v1/rooms/$roomid/members/$user/state?access_token=$token";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$roomid", encodeURIComponent(roomId));
    url = url.replace("$user", encodeURIComponent(member));
    
    if (membership === "leave") {
        $.ajax({
            url: url,
            type: "DELETE",
            contentType: "application/json; charset=utf-8",
            dataType: "json",
            success: function(data) {
                getCurrentRoomList();
            },
            error: function(err) {
                alert(JSON.stringify($.parseJSON(err.responseText)));  
            }
        });
    }
    else {
        var data = {
            membership: membership
        };
        
        $.ajax({
            url: url,
            type: "PUT",
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
    }
});

$('.joinAlias').live('click', function() {
    var roomAlias = $("#roomAlias").val();
    var url = "http://localhost:8080/matrix/client/api/v1/join/$roomalias?access_token=$token";
    url = url.replace("$token", accountInfo.access_token);
    url = url.replace("$roomalias", encodeURIComponent(roomAlias));
    $.ajax({
        url: url,
        type: "PUT",
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
