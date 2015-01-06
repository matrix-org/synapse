# Copyright 2014, 2015 OpenMarket Ltd
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

    def __init__(self, args):
        super(CaptchaConfig, self).__init__(args)
        self.recaptcha_private_key = args.recaptcha_private_key
        self.enable_registration_captcha = args.enable_registration_captcha
        self.captcha_ip_origin_is_x_forwarded = (
            args.captcha_ip_origin_is_x_forwarded
        )
        self.captcha_bypass_secret = args.captcha_bypass_secret

    @classmethod
    def add_arguments(cls, parser):
        super(CaptchaConfig, cls).add_arguments(parser)
        group = parser.add_argument_group("recaptcha")
        group.add_argument(
            "--recaptcha-private-key", type=str, default="YOUR_PRIVATE_KEY",
            help="The matching private key for the web client's public key."
        )
        group.add_argument(
            "--enable-registration-captcha", type=bool, default=False,
            help="Enables ReCaptcha checks when registering, preventing signup"
            + " unless a captcha is answered. Requires a valid ReCaptcha "
            + "public/private key."
        )
        group.add_argument(
            "--captcha_ip_origin_is_x_forwarded", type=bool, default=False,
            help="When checking captchas, use the X-Forwarded-For (XFF) header"
            + " as the client IP and not the actual client IP."
        )
        group.add_argument(
            "--captcha_bypass_secret", type=str,
            help="A secret key used to bypass the captcha test entirely."
        )
