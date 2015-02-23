window.matrixRegistration = {};

var setupCaptcha = function() {
	if (!window.matrixRegistrationConfig) {
		return;
	}
    console.log("Setting up ReCaptcha");
    var public_key = window.matrixRegistrationConfig.recaptcha_public_key;
    if (public_key === undefined) {
        console.error("No public key defined for captcha!");
        return;
    }
    Recaptcha.create(public_key,
    "regcaptcha",
    {
      theme: "red",
      callback: Recaptcha.focus_response_field
    });
};

matrixRegistration.onLoad = function() {
	setupCaptcha();
};