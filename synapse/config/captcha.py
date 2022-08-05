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

from typing import Any

from synapse.types import JsonDict

from ._base import Config, ConfigError


class CaptchaConfig(Config):
    section = "captcha"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        recaptcha_private_key = config.get("recaptcha_private_key")
        if recaptcha_private_key is not None and not isinstance(
            recaptcha_private_key, str
        ):
            raise ConfigError("recaptcha_private_key must be a string.")
        self.recaptcha_private_key = recaptcha_private_key

        recaptcha_public_key = config.get("recaptcha_public_key")
        if recaptcha_public_key is not None and not isinstance(
            recaptcha_public_key, str
        ):
            raise ConfigError("recaptcha_public_key must be a string.")
        self.recaptcha_public_key = recaptcha_public_key

        self.enable_registration_captcha = config.get(
            "enable_registration_captcha", False
        )
        self.recaptcha_siteverify_api = config.get(
            "recaptcha_siteverify_api",
            "https://www.recaptcha.net/recaptcha/api/siteverify",
        )
        self.recaptcha_template = self.read_template("recaptcha.html")
