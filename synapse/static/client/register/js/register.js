window.matrixRegistration = {
    endpoint: location.origin + "/_matrix/client/r0/register"
};

var setupCaptcha = function() {
    $.ajax({
        url: matrixRegistration.endpoint,
        method: "POST",
        data: '{}',
        complete: function(response) {
            if (response.status != 401) {
                errorFunc(response);
                return;
            }
            response = response.responseJSON;
            window.matrixRegistration.session = response.session;
            var serverExpectsCaptcha = false;
            for (var i=0; i<response.flows.length; i++) {
                var flow = response.flows[i];
                for (j=0; j<flow.stages.length; j++) {
                    var stage = flow.stages[j];
                    if ("m.login.recaptcha" === stage) {
                        serverExpectsCaptcha = true;
                        break;
                    }
                }
            }
            if (!serverExpectsCaptcha) {
                console.log("This server does not require a captcha.");
                return;
            }
            console.log("Setting up ReCaptcha for "+matrixRegistration.endpoint);
            var public_key = response.params["m.login.recaptcha"].public_key;
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
        }
    })
};

var submitCaptcha = function(user, pwd) {
    var challengeToken = Recaptcha.get_challenge();
    var captchaEntry = Recaptcha.get_response();
    var data = {
        auth: {
            type: "m.login.recaptcha",
            challenge: challengeToken,
            response: captchaEntry,
            session: window.matrixRegistration.session,
        },
        username: user,
        password: pwd,
    };
    console.log("Submitting captcha");
    $.ajax({
        url: matrixRegistration.endpoint,
        method: "POST",
        data: JSON.stringify(data),
        complete: function(response) {
            if (response.responseJSON.errcode) {
                if (response.status != 401) {
                    Recaptcha.reload();
                }
                errorFunc(response);
                return
            }
            console.log("Success -> "+JSON.stringify(response));
            submitPassword(user, pwd);
        }
    })
};

var submitPassword = function(user, pwd) {
    console.log("Registering...");
    var data = {
        auth: {
            type: "m.login.dummy",
            session: window.matrixRegistration.session,
        },
        username: user,
        password: pwd,
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
