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

    def read_config(self, config):
        self.recaptcha_private_key = config["recaptcha_private_key"]
        self.recaptcha_public_key = config["recaptcha_public_key"]
        self.enable_registration_captcha = config["enable_registration_captcha"]
        self.captcha_bypass_secret = config.get("captcha_bypass_secret")
        self.recaptcha_siteverify_api = config["recaptcha_siteverify_api"]

    def default_config(self, **kwargs):
        return """\
        ## Captcha ##
        # See docs/CAPTCHA_SETUP for full details of configuring this.

        # This Home Server's ReCAPTCHA public key.
        recaptcha_public_key: "YOUR_PUBLIC_KEY"

        # This Home Server's ReCAPTCHA private key.
        recaptcha_private_key: "YOUR_PRIVATE_KEY"

        # Enables ReCaptcha checks when registering, preventing signup
        # unless a captcha is answered. Requires a valid ReCaptcha
        # public/private key.
        enable_registration_captcha: False

        # A secret key used to bypass the captcha test entirely.
        #captcha_bypass_secret: "YOUR_SECRET_HERE"

        # The API endpoint to use for verifying m.login.recaptcha responses.
        recaptcha_siteverify_api: "https://www.google.com/recaptcha/api/siteverify"
        """
