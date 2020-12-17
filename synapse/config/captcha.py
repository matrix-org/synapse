# Copyright 2014-2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ._base import Config


class CaptchaConfig(Config):
    section = "captcha"

    def read_config(self, config, **kwargs):
        self.recaptcha_private_key = config.get("recaptcha_private_key")
        self.recaptcha_public_key = config.get("recaptcha_public_key")
        self.enable_registration_captcha = config.get(
            "enable_registration_captcha", False
        )
        self.recaptcha_siteverify_api = config.get(
            "recaptcha_siteverify_api",
            "https://www.recaptcha.net/recaptcha/api/siteverify",
        )
        self.recaptcha_template = self.read_templates(
            ["recaptcha.html"], autoescape=True
        )[0]
        self.altcaptcha_private_key = config.get("altcaptcha_private_key")
        self.altcaptcha_public_key = config.get("altcaptcha_public_key")
        self.altcaptcha_callback_class_target = config.get("altcaptcha_callback_class_target","h-captcha")
        self.altcaptcha_template_script = config.get("altcaptcha_template_script","https://hcaptcha.com/1/api.js")
        self.altcaptcha_template_script2 = config.get("altcaptcha_template_script2", self.altcaptcha_template_script)
        self.altcaptcha_response_template = config.get("altcaptcha_response_template","h-captcha-response")
        self.enable_registration_altcaptcha = config.get(
            "enable_registration_altcaptcha", False
        )
        self.altcaptcha_siteverify_api = config.get(
            "altcaptcha_siteverify_api", "https://hcaptcha.com/siteverify",
        )
        self.altcaptcha_siteverify_api_response = config.get(
            "altcaptcha_siteverify_api_response", "response",
        )
        self.altcaptcha_template = self.read_templates(
            ["altcaptcha.html"], autoescape=True
        )[0]
        
    def generate_config_section(self, **kwargs):
        return """\
        ## Captcha ##
        # See docs/CAPTCHA_SETUP.md for full details of configuring this.

        # This homeserver's ReCAPTCHA public key. Must be specified if
        # enable_registration_captcha is enabled.
        #
        #recaptcha_public_key: "YOUR_PUBLIC_KEY"

        # This homeserver's ReCAPTCHA private key. Must be specified if
        # enable_registration_captcha is enabled.
        #
        #recaptcha_private_key: "YOUR_PRIVATE_KEY"

        # The API endpoint to use for verifying m.login.recaptcha responses.
        # Defaults to "https://www.recaptcha.net/recaptcha/api/siteverify".
        #
        #recaptcha_siteverify_api: "https://my.recaptcha.site"

        # Uncomment to enable ReCaptcha checks when registering, preventing signup
        # unless a captcha is answered. Requires a valid ReCaptcha
        # public/private key. Defaults to 'false'.
        #
        #enable_registration_captcha: true

        ## altCaptcha ##
        # See docs/CAPTCHA_SETUP.md for full details of configuring this.
        # This homeserver's altCAPTCHA public key. Must be specified if
        # enable_registration_altcaptcha is enabled.
        #
        #altcaptcha_public_key: "YOUR_PUBLIC_KEY"

        # This homeserver's altCAPTCHA private key. Must be specified if
        # enable_registration_altcaptcha is enabled.
        #
        #altcaptcha_private_key: "YOUR_PRIVATE_KEY"

        # This is the callback class used for altcaptcha validation, it is an 
        # implementation specific detail used in the altcaptcha page for result.
        # validation. Example: "frc-captcha" or "h-captcha"
        #
        #altcaptcha_callback_class_target: "IMPLEMENTATION_SPECIFIC_CALLBACK_CLASS_TARGET"

        # This is the captcha script used in the template altcaptcha page.
        # Example: https://cdn.jsdelivr.net/npm/friendly-challenge@0.6.1/widget.module.min.js or 
        # https://hcaptcha.com/1/api.js to use either FriendlyCaptcha or hCaptcha
        #
        #altcaptcha_template_script: "URL_TO_CAPTCHA_SCRIPT"

        # The API endpoint to use for verifying org.matrix.msc2745.login.altcaptcha responses.
        # Defaults to "https://hcaptcha.com/siteverify".
        #
        #altcaptcha_siteverify_api: "https://hcaptcha.com/siteverify"

        # This value is used for sending the altcaptcha to validate via the api
        # For some alternative captcha's they may use "solution" to validate
        # The default value for this is "response"
        #
        #altcaptcha_siteverify_api_response: "response"

        # This is the response name used for the captcha system you have configured
        # Used in synapse/rest/client/v2_alpha/auth.py
        # Example: "frc-captcha-solution" or "h-captcha-response"
        #
        #altcaptcha_response_template: "CAPTCHA_RESPONSE_TEMPLATE"

        # Uncomment to enable altcaptcha checks when registering, preventing signup
        # unless a captcha is answered. Requires a valid altcaptcha
        # public/private key. Defaults to 'false'.
        #
        #enable_registration_altcaptcha: true
        """
