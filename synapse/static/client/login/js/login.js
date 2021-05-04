window.matrixLogin = {
    endpoint: location.origin + "/_matrix/client/r0/login",
    serverAcceptsPassword: false,
    serverAcceptsSso: false,
};

// Titles get updated through the process to give users feedback.
const TITLE_PRE_AUTH = "Log in with one of the following methods";
const TITLE_POST_AUTH = "Logging in...";

// The cookie used to store the original query parameters when using SSO.
const COOKIE_KEY = "synapse_login_fallback_qs";

/*
 * Submit a login request.
 *
 * type: The login type as a string (e.g. "m.login.foo").
 * data: An object of data specific to the login type.
 * extra: (Optional) An object to search for extra information to send with the
 *     login request, e.g. device_id.
 * callback: (Optional) Function to call on successful login.
 */
function submitLogin(type, data, extra, callback) {
    console.log("Logging in with " + type);
    setTitle(TITLE_POST_AUTH);

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
}

/*
 * Display an error to the user and show the login form again.
 */
function errorFunc(err) {
    // We want to show the error to the user rather than redirecting immediately to the
    // SSO portal (if SSO is the only login option), so we inhibit the redirect.
    showLogin(true);

    if (err.responseJSON && err.responseJSON.error) {
        setFeedbackString(err.responseJSON.error + " (" + err.responseJSON.errcode + ")");
    }
    else {
        setFeedbackString("Request failed: " + err.status);
    }
}

/*
 * Display an error to the user.
 */
function setFeedbackString(text) {
    $("#feedback").text(text);
}

/*
 * (Maybe) Show the login forms.
 *
 * This actually does a few unrelated functions:
 *
 * * Configures the SSO redirect URL to come back to this page.
 * * Configures and shows the SSO form, if the server supports SSO.
 * * Otherwise, shows the password form.
 */
function showLogin(inhibitRedirect) {
    setTitle(TITLE_PRE_AUTH);

    // If inhibitRedirect is false, and SSO is the only supported login method,
    // we can redirect straight to the SSO page.
    if (matrixLogin.serverAcceptsSso) {
        // Set the redirect to come back to this page, a login token will get
        // added as a query parameter and handled after the redirect.
        $("#sso_redirect_url").val(window.location.origin + window.location.pathname);

        // Before submitting SSO, set the current query parameters into a cookie
        // for retrieval later.
        var qs = parseQsFromUrl();
        setCookie(COOKIE_KEY, JSON.stringify(qs));

        // If password is not supported and redirects are allowed, then submit
        // the form (redirecting to the SSO provider).
        if (!inhibitRedirect && !matrixLogin.serverAcceptsPassword) {
            $("#sso_form").submit();
            return;
        }

        // Otherwise, show the SSO form
        $("#sso_flow").show();
    }

    if (matrixLogin.serverAcceptsPassword) {
        $("#password_flow").show();
    }

    // If neither password or SSO are supported, show an error to the user.
    if (!matrixLogin.serverAcceptsPassword && !matrixLogin.serverAcceptsSso) {
        $("#no_login_types").show();
    }

    $("#loading").hide();
}

/*
 * Hides the forms and shows a loading throbber.
 */
function showSpinner() {
    $("#password_flow").hide();
    $("#sso_flow").hide();
    $("#no_login_types").hide();
    $("#loading").show();
}

/*
 * Helper to show the page's main title.
 */
function setTitle(title) {
    $("#title").text(title);
}

/*
 * Query the login endpoint for the homeserver's supported flows.
 *
 * This populates matrixLogin.serverAccepts* variables.
 */
function fetchLoginFlows(cb) {
    $.get(matrixLogin.endpoint, function(response) {
        for (var i = 0; i < response.flows.length; i++) {
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

/*
 * Called on load to fetch login flows and attempt SSO login (if a token is available).
 */
matrixLogin.onLoad = function() {
    fetchLoginFlows(function() {
        // (Maybe) attempt logging in via SSO if a token is available.
        if (!tryTokenLogin()) {
            showLogin(false);
        }
    });
};

/*
 * Submit simple user & password login.
 */
matrixLogin.passwordLogin = function() {
    var user = $("#user_id").val();
    var pwd = $("#password").val();

    setFeedbackString("");

    showSpinner();
    submitLogin(
        "m.login.password",
        {user: user, password: pwd},
        parseQsFromUrl());
};

/*
 * The onLogin function gets called after a successful login.
 *
 * It is expected that implementations override this to be notified when the
 * login is complete. The response to the login call is provided as the single
 * parameter.
 */
matrixLogin.onLogin = function(response) {
    // clobber this function
    console.warn("onLogin - This function should be replaced to proceed.");
};

/*
 * Process the query parameters from the current URL into an object.
 */
function parseQsFromUrl() {
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
}

/*
 * Process the cookies and return an object.
 */
function parseCookies() {
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
}

/*
 * Set a cookie that is valid for 1 hour.
 */
function setCookie(key, value) {
    // The maximum age is set in seconds.
    var maxAge = 60 * 60;
    // Set the cookie, this defaults to the current domain and path.
    document.cookie = key + "=" + encodeURIComponent(value) + ";max-age=" + maxAge + ";sameSite=lax";
}

/*
 * Removes a cookie by key.
 */
function deleteCookie(key) {
    // Delete a cookie by setting the expiration to 0. (Note that the value
    // doesn't matter.)
    document.cookie = key + "=deleted;expires=0";
}

/*
 * Submits the login token if one is found in the query parameters. Returns a
 * boolean of whether the login token was found or not.
 */
function tryTokenLogin() {
    // Check if the login token is in the query parameters.
    var qs = parseQsFromUrl();

    var loginToken = qs.loginToken;
    if (!loginToken) {
        return false;
    }

    // Retrieve the original query parameters (from before the SSO redirect).
    // They are stored as JSON in a cookie.
    var cookies = parseCookies();
    var originalQueryParams = JSON.parse(cookies[COOKIE_KEY] || "{}")

    // If the login is successful, delete the cookie.
    function callback() {
        deleteCookie(COOKIE_KEY);
    }

    submitLogin(
        "m.login.token",
        {token: loginToken},
        originalQueryParams,
        callback);

    return true;
}
