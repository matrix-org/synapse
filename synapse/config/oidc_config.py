# -*- coding: utf-8 -*-
# Copyright 2020 Quentin Gliech
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

from synapse.python_dependencies import DependencyException, check_requirements

from ._base import Config, ConfigError


class OIDCConfig(Config):
    section = "oidc"

    def read_config(self, config, **kwargs):
        self.oidc_enabled = False

        oidc_config = config.get("oidc_config")

        if not oidc_config or not oidc_config.get("enabled", True):
            return

        try:
            check_requirements("oidc")
        except DependencyException as e:
            raise ConfigError(e.message)

        public_baseurl = self.public_baseurl
        if public_baseurl is None:
            raise ConfigError("oidc_config requires a public_baseurl to be set")
        self.oidc_callback_url = public_baseurl + "_synapse/oidc/callback"

        self.oidc_enabled = True
        self.oidc_issuer = oidc_config["issuer"]
        self.oidc_client_id = oidc_config["client_id"]
        self.oidc_client_secret = oidc_config["client_secret"]
        self.oidc_scopes = oidc_config.get("scopes", ["openid"])

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # Enable OpenID Connect for registration and login. Uses authlib.
        #
        #oidc_config:
        #   enabled: true
        #   issuer: "https://accounts.example.com/"
        #   client_id: "provided-by-your-issuer"
        #   client_secret: "provided-by-your-issuer"
        #   scopes: ["openid"]
        """
