window.matrixRegistration = {
    endpoint: location.origin + "/_matrix/client/api/v1/register"
};

var setupCaptcha = function() {
    if (!window.matrixRegistrationConfig) {
        return;
    }
    $.get(matrixRegistration.endpoint, function(response) {
        var serverExpectsCaptcha = false;
        for (var i=0; i<response.flows.length; i++) {
            var flow = response.flows[i];
            if ("m.login.recaptcha" === flow.type) {
                serverExpectsCaptcha = true;
                break;
            }
        }
        if (!serverExpectsCaptcha) {
            console.log("This server does not require a captcha.");
            return;
        }
        console.log("Setting up ReCaptcha for "+matrixRegistration.endpoint);
        var public_key = window.matrixRegistrationConfig.recaptcha_public_key;
        if (public_key === undefined) {
            console.error("No public key defined for captcha!");
            setFeedbackString("Misconfigured captcha for server. Contact server admin.");
            return;
        }
        Recaptcha.create(public_key,
        "regcaptcha",
        {
            theme: "red",
            callback: Recaptcha.focus_response_field
        });
        window.matrixRegistration.isUsingRecaptcha = true;
    }).error(errorFunc);
    
};

var submitCaptcha = function(user, pwd) {
    var challengeToken = Recaptcha.get_challenge();
    var captchaEntry = Recaptcha.get_response();
    var data = {
        type: "m.login.recaptcha",
        challenge: challengeToken,
        response: captchaEntry
    };
    console.log("Submitting captcha");
    $.post(matrixRegistration.endpoint, JSON.stringify(data), function(response) {
        console.log("Success -> "+JSON.stringify(response));
        submitPassword(user, pwd, response.session);
    }).error(function(err) {
        Recaptcha.reload();
        errorFunc(err);
    });
};

var submitPassword = function(user, pwd, session) {
    console.log("Registering...");
    var data = {
        type: "m.login.password",
        user: user,
        password: pwd,
        session: session
    };
    $.post(matrixRegistration.endpoint, JSON.stringify(data), function(response) {
        matrixRegistration.onRegistered(
            response.home_server, response.user_id, response.access_token
        );
    }).error(errorFunc);
};

var errorFunc = function(err) {
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

matrixRegistration.onLoad = function() {
    setupCaptcha();
};

matrixRegistration.signUp = function() {
    var user = $("#desired_user_id").val();
    if (user.length == 0) {
        setFeedbackString("Must specify a username.");
        return;
    }
    var pwd1 = $("#pwd1").val();
    var pwd2 = $("#pwd2").val();
    if (pwd1.length < 6) {
        setFeedbackString("Password: min. 6 characters.");
        return;
    }
    if (pwd1 != pwd2) {
        setFeedbackString("Passwords do not match.");
        return;
    }
    if (window.matrixRegistration.isUsingRecaptcha) {
        submitCaptcha(user, pwd1);
    }
    else {
        submitPassword(user, pwd1);
    }
};

matrixRegistration.onRegistered = function(hs_url, user_id, access_token) {
    // clobber this function
    console.log("onRegistered - This function should be replaced to proceed.");
};
