window.matrixLogin = {
    endpoint: location.origin + "/_matrix/client/r0/login",
    serverAcceptsPassword: false,
    serverAcceptsSso: false,
};

var title_pre_auth = "Log in with one of the following methods";
var title_post_auth = "Logging in...";

var submitLogin = function(type, data) {
    console.log("Logging in with " + type);
    set_title(title_post_auth);

    // Add the login type.
    data.type = type;

    // Add the device information, if it was provided.
    var qs = parseQsFromUrl();
    if (qs.device_id) {
        data.device_id = qs.device_id;
    }
    if (qs.initial_device_display_name) {
        data.initial_device_display_name = qs.initial_device_display_name;
    }

    $.post(matrixLogin.endpoint, JSON.stringify(data), function(response) {
        matrixLogin.onLogin(response);
    }).fail(errorFunc);
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
    // Set the redirect to come back to this page, a login token will get added
    // and handled after the redirect.
    $("#sso_redirect_url").val(window.location.href);

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
    }).fail(errorFunc);
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
    submitLogin("m.login.password", {user: user, password: pwd});
};

matrixLogin.onLogin = function(response) {
    // clobber this function
    console.warn("onLogin - This function should be replaced to proceed.");
};

/*
 * Process the query parameters from the current URL into an object.
 */
var parseQsFromUrl = function() {
    var pos = window.location.href.indexOf("?");
    if (pos == -1) {
        return {};
    }
    var query = window.location.href.substr(pos + 1);

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

/*
 * Submits the login token if one is found in the query parameters. Returns a
 * boolean of whether the login token was found or not.
 */
var try_token = function() {
    var qs = parseQsFromUrl();

    var loginToken = qs.loginToken;
    if (!loginToken) {
        return false;
    }

    submitLogin("m.login.token", {token: loginToken});

    return true;
};
