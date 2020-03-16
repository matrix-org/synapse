# Overview
Captcha can be enabled for this home server. This file explains how to do that.
The captcha mechanism used is Google's ReCaptcha. This requires API keys from Google.

## Getting keys

Requires a site/secret key pair from:

<https://developers.google.com/recaptcha/>

Must be a reCAPTCHA v2 key using the "I'm not a robot" Checkbox option

## Setting ReCaptcha Keys

The keys are a config option on the home server config. If they are not
visible, you can generate them via `--generate-config`. Set the following value:

    recaptcha_public_key: YOUR_SITE_KEY
    recaptcha_private_key: YOUR_SECRET_KEY

In addition, you MUST enable captchas via:

    enable_registration_captcha: true

## Configuring IP used for auth

The ReCaptcha API requires that the IP address of the user who solved the
captcha is sent. If the client is connecting through a proxy or load balancer,
it may be required to use the `X-Forwarded-For` (XFF) header instead of the origin
IP address. This can be configured using the `x_forwarded` directive in the
listeners section of the homeserver.yaml configuration file.
