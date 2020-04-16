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
        self.oidc_discover = oidc_config.get("discover", True)
        self.oidc_issuer = oidc_config["issuer"]
        self.oidc_client_id = oidc_config["client_id"]
        self.oidc_client_secret = oidc_config["client_secret"]
        self.oidc_scopes = oidc_config.get("scopes", ["openid"])
        self.oidc_authorization_endpoint = oidc_config.get("authorization_endpoint")
        self.oidc_token_endpoint = oidc_config.get("token_endpoint")
        self.oidc_userinfo_endpoint = oidc_config.get("userinfo_endpoint")
        self.oidc_jwks_uri = oidc_config.get("jwks_uri")
        self.oidc_response_type = oidc_config.get("response_type", "code")

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # Enable OpenID Connect for registration and login. Uses authlib.
        #
        oidc_config:
            # enable OpenID Connect. Defaults to false.
            #
            #enabled: true

            # use the OIDC discovery mechanism to discover endpoints. Defaults to true.
            #
            #discover: true

            # the OIDC issuer. Used to validate tokens and discover the providers endpoints. Required.
            #
            #issuer: "https://accounts.example.com/"

            # oauth2 client id to use. Required.
            #
            #client_id: "provided-by-your-issuer"

            # oauth2 client secret to use. Required.
            #
            #client_secret: "provided-by-your-issuer"

            # list of scopes to ask. This should include the "openid" scope. Defaults to ["openid"].
            #
            #scopes: ["openid"]

            # the oauth2 authorization endpoint. Required if provider discovery is disabled.
            #
            #authorization_endpoint: "https://accounts.example.com/oauth2/auth"

            # the oauth2 token endpoint. Required if provider discovery is disabled.
            #
            #token_endpoint: "https://accounts.example.com/oauth2/token"

            # the OIDC userinfo endpoint. Required if discovery is disabled and the "openid" scope is not asked.
            #
            #userinfo_endpoint: "https://accounts.example.com/userinfo"

            # URI where to fetch the JWKS. Required if discovery is disabled and the "openid" scope is used.
            #
            #jwks_uri: "https://accounts.example.com/.well-known/jwks.json"

            # response type to use. For now, only "code" is supported. Defaults to "code".
            #
            #response_type: "code"
        """
