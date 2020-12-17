# Overview

Captchas can be enabled for this home server. This file explains how to do that.
The captcha mechanism supports Google's ReCaptcha and or an alternative captcha
such as hCaptcha, Friendly Captcha, or similar implentations. This requires
API keys from Google or the alternative captcha service. You can also enable both
captcha systems to work at the same time. If they are both enabled the alternative
captcha will prompt "Start Authentication" first which will open a new window and
then ReCaptcha will become active after the alternate Captcha has been solved.

## ReCaptcha

### Getting keys

Requires a site/secret key pair from:

<https://developers.google.com/recaptcha/>

Must be a reCAPTCHA v2 key using the "I'm not a robot" Checkbox option

### Setting ReCaptcha Keys

The keys are a config option on the home server config. If they are not
visible, you can generate them via `--generate-config`. Set the following value:

    recaptcha_public_key: YOUR_SITE_KEY
    recaptcha_private_key: YOUR_SECRET_KEY

In addition, you MUST enable captchas via:

    enable_registration_captcha: true

### Configuring IP used for auth

The ReCaptcha API requires that the IP address of the user who solved the
captcha is sent. If the client is connecting through a proxy or load balancer,
it may be required to use the `X-Forwarded-For` (XFF) header instead of the origin
IP address. This can be configured using the `x_forwarded` directive in the
listeners section of the homeserver.yaml configuration file.

## altCaptcha

Alternative captcha's are supported that:
    1) Use no more than 2 scripts to be imbeded.
    2) Use a post request API call to implement captcha validation.

By default altCaptcha provides default settings set to hCaptcha, but can be
configured to use similar captcha implentations like Friendly Captcha.

### Getting altCaptcha keys

Requires a site/secret key pair from:

<https://www.hcaptcha.com/> or <https://friendlycaptcha.com/>

### Setting altCaptcha Keys

The keys are a config option on the home server config. If they are not
visible, you can generate them via `--generate-config`. Set the following value:

    altcaptcha_public_key: YOUR_SITE_KEY
    altcaptcha_private_key: YOUR_SECRET_KEY

### Scripts to embed and other settings

To use an alternative captcha that is not hCaptcha you will need to customize
the following settings as well.

#### Template Embed Scripts

The template embed scripts are used to customize the scripts that will be embed
in the fallback altcaptcha.html template page. These are the dependencies required
to load the desired captcha. Some modern systems use a WASM/Module script to
implement advanced captcha functionality and need to be specified via one of the
two altcaptcha_template_script configuration options.
The default value is "https://hcaptcha.com/1/api.js".
If altcaptcha_template_script2 is not configured it is set to the value of
altcaptcha_template_script to avoid 404 errors in the second script tag.

    altcaptcha_template_script: URL_TO_CAPTCHA_SCRIPT_TO_EMBED
    altcaptcha_template_script2: URL_TO_CAPTCHA_SCRIPT2_TO_EMBED_WASM_MODULE

#### Additional template settings

For embedding the alternative captcha you also need to specify the div class that
it binds to for display using the altcaptcha_callback_class_target
Examples: "h-captcha", "frc-captcha"
The default value is "h-captcha".

    altcaptcha_callback_class_target: ALT_CAPTCHA_BINDING_CLASS

The name of the captcha response also needs to be configured for alternative captchas.
This effects the synapse/api/client/v2_alpha/auth.py API endpoint data parsing.
The default value is "h-captcha-response".

    altcaptcha_response_template: NAME_OF_RESPONSE

The name of the solution parameter to submit for validation may also need to be
configured. For example to use Friendly capatcha the value needed is "solution".
The default value is "response".

    altcaptcha_siteverify_api_response: PARAMETER_NAME_FOR_API_CAPTCHA_VALIDATION

In addition, you MUST enable altCaptcha via:

    enable_registration_altcaptcha: true

### Configuring IP used for user auth

Most Captcha API's require that the IP address of the user who solved the
captcha is sent. If the client is connecting through a proxy or load balancer,
it may be required to use the `X-Forwarded-For` (XFF) header instead of the origin
IP address. This can be configured using the `x_forwarded` directive in the
listeners section of the homeserver.yaml configuration file.
