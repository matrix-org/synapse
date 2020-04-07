window.matrixLogin = {
    endpoint: location.origin + "/_matrix/client/r0/login",
    serverAcceptsPassword: false,
    serverAcceptsSso: false,
};

var title_pre_auth = "Log in with one of the following methods";
var title_post_auth = "Logging in...";

var submitPassword = function(user, pwd) {
    console.log("Logging in with password...");
    set_title(title_post_auth);
    var data = {
        type: "m.login.password",
        user: user,
        password: pwd,
    };
    $.post(matrixLogin.endpoint, JSON.stringify(data), function(response) {
        matrixLogin.onLogin(response);
    }).error(errorFunc);
};

var submitToken = function(loginToken) {
    console.log("Logging in with login token...");
    set_title(title_post_auth);
    var data = {
        type: "m.login.token",
        token: loginToken
    };
    $.post(matrixLogin.endpoint, JSON.stringify(data), function(response) {
        matrixLogin.onLogin(response);
    }).error(errorFunc);
};

var errorFunc = function(err) {
    // We want to show the error to the user rather than redirecting immediately to the
    // SSO portal (if SSO is the only login option), so we inhibit the redirect.
    show_login(true);

    if (err.responseJSON && err.responseJSON.error) {
        setFeedbackString(err.responseJSON.error + " (" + err.responseJSON.errcode + ")");
    }
    else {
        setFeedbackString("Request failed: " + err.status);
    }
};

var setFeedbackString = function(text) {
    $("#feedback").text(text);
};

var show_login = function(inhibit_redirect) {
    var this_page = window.location.origin + window.location.pathname;
    $("#sso_redirect_url").val(this_page);

    // If inhibit_redirect is false, and SSO is the only supported login method, we can
    // redirect straight to the SSO page
    if (matrixLogin.serverAcceptsSso) {
        if (!inhibit_redirect && !matrixLogin.serverAcceptsPassword) {
            $("#sso_form").submit();
            return;
        }

        // Otherwise, show the SSO form
        $("#sso_flow").show();
    }

    if (matrixLogin.serverAcceptsPassword) {
        $("#password_flow").show();
    }

    if (!matrixLogin.serverAcceptsPassword && !matrixLogin.serverAcceptsSso) {
        $("#no_login_types").show();
    }

    set_title(title_pre_auth);

    $("#loading").hide();
};

var show_spinner = function() {
    $("#password_flow").hide();
    $("#sso_flow").hide();
    $("#no_login_types").hide();
    $("#loading").show();
};

var set_title = function(title) {
    $("#title").text(title);
};

var fetch_info = function(cb) {
    $.get(matrixLogin.endpoint, function(response) {
        var serverAcceptsPassword = false;
        for (var i=0; i<response.flows.length; i++) {
            var flow = response.flows[i];
            if ("m.login.sso" === flow.type) {
                matrixLogin.serverAcceptsSso = true;
                console.log("Server accepts SSO");
            }
            if ("m.login.password" === flow.type) {
                matrixLogin.serverAcceptsPassword = true;
                console.log("Server accepts password");
            }
        }

        cb();
    }).error(errorFunc);
}

matrixLogin.onLoad = function() {
    fetch_info(function() {
        if (!try_token()) {
            show_login(false);
        }
    });
};

matrixLogin.password_login = function() {
    var user = $("#user_id").val();
    var pwd = $("#password").val();

    setFeedbackString("");

    show_spinner();
    submitPassword(user, pwd);
};

matrixLogin.onLogin = function(response) {
    // clobber this function
    console.log("onLogin - This function should be replaced to proceed.");
    console.log(response);
};

var parseQsFromUrl = function(query) {
    var result = {};
    query.split("&").forEach(function(part) {
        var item = part.split("=");
        var key = item[0];
        var val = item[1];

        if (val) {
            val = decodeURIComponent(val);
        }
        result[key] = val
    });
    return result;
};

var try_token = function() {
    var pos = window.location.href.indexOf("?");
    if (pos == -1) {
        return false;
    }
    var qs = parseQsFromUrl(window.location.href.substr(pos+1));

    var loginToken = qs.loginToken;

    if (!loginToken) {
        return false;
    }

    submitToken(loginToken);

    return true;
};
