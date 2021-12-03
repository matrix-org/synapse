# Overview
A captcha can be enabled on your homeserver to help prevent bots from registering
accounts. Synapse currently uses Google's reCAPTCHA service which requires API keys
from Google.

## Getting API keys

1. Create a new site at <https://www.google.com/recaptcha/admin/create>
1. Set the label to anything you want
1. Set the type to reCAPTCHA v2 using the "I'm not a robot" Checkbox option.
This is the only type of captcha that works with Synapse.
1. Add the public hostname for your server, as set in `public_baseurl`
in `homeserver.yaml`, to the list of authorized domains. If you have not set
`public_baseurl`, use `server_name`.
1. Agree to the terms of service and submit.
1. Copy your site key and secret key and add them to your `homeserver.yaml`
configuration file
    ```yaml
    recaptcha_public_key: YOUR_SITE_KEY
    recaptcha_private_key: YOUR_SECRET_KEY
    ```
1. Enable the CAPTCHA for new registrations
    ```yaml
    enable_registration_captcha: true
    ```
1. Go to the settings page for the CAPTCHA you just created
1. Uncheck the "Verify the origin of reCAPTCHA solutions" checkbox so that the
captcha can be displayed in any client. If you do not disable this option then you
must specify the domains of every client that is allowed to display the CAPTCHA.

## Configuring IP used for auth

The reCAPTCHA API requires that the IP address of the user who solved the
CAPTCHA is sent. If the client is connecting through a proxy or load balancer,
it may be required to use the `X-Forwarded-For` (XFF) header instead of the origin
IP address. This can be configured using the `x_forwarded` directive in the
listeners section of the `homeserver.yaml` configuration file.
