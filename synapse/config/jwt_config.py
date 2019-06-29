# -*- coding: utf-8 -*-
# Copyright 2015 Niklas Riekenbrauck
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

from ._base import Config, ConfigError

MISSING_JWT = """Missing jwt library. This is required for jwt login.

    Install by running:
        pip install pyjwt
    """


class JWTConfig(Config):
    def read_config(self, config, **kwargs):
        jwt_config = config.get("jwt_config", None)
        if jwt_config:
            self.jwt_enabled = jwt_config.get("enabled", False)
            self.jwt_secret = jwt_config["secret"]
            self.jwt_algorithm = jwt_config["algorithm"]

            try:
                import jwt

                jwt  # To stop unused lint.
            except ImportError:
                raise ConfigError(MISSING_JWT)
        else:
            self.jwt_enabled = False
            self.jwt_secret = None
            self.jwt_algorithm = None

    def generate_config_section(self, **kwargs):
        return """\
        # The JWT needs to contain a globally unique "sub" (subject) claim.
        #
        #jwt_config:
        #   enabled: true
        #   secret: "a secret"
        #   algorithm: "HS256"
        """
