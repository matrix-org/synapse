var accountInfo = {};

var showLoggedIn = function(data) {
    accountInfo = data;
    $(".loggedin").css({visibility: "visible"});
    $("#welcomeText").text("Welcome " + accountInfo.user_id+". Your access token is:  " +
                           accountInfo.access_token);    
};

$('.register').live('click', function() {
    var user = $("#user").val();
    var password = $("#password").val();
    $.ajax({
        url: "http://localhost:8008/_matrix/client/api/v1/register",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({ user: user, password: password, type: "m.login.password" }),
        dataType: "json",
        success: function(data) {
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

var login = function(user, password) {
    $.ajax({
        url: "http://localhost:8008/_matrix/client/api/v1/login",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({ user: user, password: password, type: "m.login.password" }),
        dataType: "json",
        success: function(data) {
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
};

$('.login').live('click', function() {
    var user = $("#userLogin").val();
    var password = $("#passwordLogin").val();
    $.getJSON("http://localhost:8008/_matrix/client/api/v1/login", function(data) {
        if (data.flows[0].type !== "m.login.password") {
            alert("I don't know how to login with this type: " + data.type);
            return;
        }
        login(user, password);
    });
});

$('.logout').live('click', function() {
    accountInfo = {};
    $("#imSyncText").text("");
    $(".loggedin").css({visibility: "hidden"});
});

$('.testToken').live('click', function() {
    var url = "http://localhost:8008/_matrix/client/api/v1/initialSync?access_token=" + accountInfo.access_token + "&limit=1";
    $.getJSON(url, function(data) {
         $("#imSyncText").text(JSON.stringify(data, undefined, 2));
    }).fail(function(err) {
        $("#imSyncText").text(JSON.stringify($.parseJSON(err.responseText)));
    });
});
