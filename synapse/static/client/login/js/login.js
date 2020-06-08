window.matrixLogin = {
    endpoint: location.origin + "/_matrix/client/r0/login",
    serverAcceptsPassword: false,
    serverAcceptsSso: false,
};

// Titles get updated through the process to give users feedback.
var TITLE_PRE_AUTH = "Log in with one of the following methods";
var TITLE_POST_AUTH = "Logging in...";

// The cookie used to store the original query parameters when using SSO.
var COOKIE_KEY = "synapse_login_fallback_qs";

/*
 * Submit a login request.
 *
 * type: The login type as a string (e.g. "m.login.foo").
 * data: An object of data specific to the login type.
 * extra: (Optional) An object to search for extra information to send with the
 *     login request, e.g. device_id.
 * callback: (Optional) Function to call on successful login.
 */
var submitLogin = function(type, data, extra, callback) {
    console.log("Logging in with " + type);
    set_title(TITLE_POST_AUTH);

    // Add the login type.
    data.type = type;

    // Add the device information, if it was provided.
    if (extra.device_id) {
        data.device_id = extra.device_id;
    }
    if (extra.initial_device_display_name) {
        data.initial_device_display_name = extra.initial_device_display_name;
    }

    $.post(matrixLogin.endpoint, JSON.stringify(data), function(response) {
        if (callback) {
            callback();
        }
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
    var this_page = window.location.origin + window.location.pathname;
    $("#sso_redirect_url").val(this_page);

    // If inhibit_redirect is false, and SSO is the only supported login method,
    // we can redirect straight to the SSO page.
    if (matrixLogin.serverAcceptsSso) {
        // Before submitting SSO, set the current query parameters into a cookie
        // for retrieval later.
        var qs = parseQsFromUrl();
        setCookie(COOKIE_KEY, JSON.stringify(qs));

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

    set_title(TITLE_PRE_AUTH);

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
    submitLogin(
        "m.login.password",
        {user: user, password: pwd},
        parseQsFromUrl());
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
        result[key] = val;
    });
    return result;
};

/*
 * Process the cookies and return an object.
 */
var parseCookies = function() {
    var allCookies = document.cookie;
    var result = {};
    allCookies.split(";").forEach(function(part) {
        var item = part.split("=");
        // Cookies might have arbitrary whitespace between them.
        var key = item[0].trim();
        // You can end up with a broken cookie that doesn't have an equals sign
        // in it. Set to an empty value.
        var val = (item[1] || "").trim();
        // Values might be URI encoded.
        if (val) {
            val = decodeURIComponent(val);
        }
        result[key] = val;
    });
    return result;
};

/*
 * Set a cookie that is valid for 1 hour.
 */
var setCookie = function(key, value) {
    // The maximum age is set in seconds.
    var maxAge = 60 * 60;
    // Set the cookie, this defaults to the current domain and path.
    document.cookie = key + "=" + encodeURIComponent(value) + ";max-age=" + maxAge + ";sameSite=lax";
};

/*
 * Removes a cookie by key.
 */
var deleteCookie = function(key) {
    // Delete a cookie by setting the expiration to 0. (Note that the value
    // doesn't matter.)
    document.cookie = key + "=deleted;expires=0";
};

/*
 * Submits the login token if one is found in the query parameters. Returns a
 * boolean of whether the login token was found or not.
 */
var try_token = function() {
    // Check if the login token is in the query parameters.
    var qs = parseQsFromUrl();

    var loginToken = qs.loginToken;
    if (!loginToken) {
        return false;
    }

    // Retrieve the original query parameters (from before the SSO redirect).
    // They are stored as JSON in a cookie.
    var cookies = parseCookies();
    var original_query_params = JSON.parse(cookies[COOKIE_KEY] || "{}")

    // If the login is successful, delete the cookie.
    var callback = function() {
        deleteCookie(COOKIE_KEY);
    }

    submitLogin(
        "m.login.token",
        {token: loginToken},
        original_query_params,
        callback);

    return true;
};
