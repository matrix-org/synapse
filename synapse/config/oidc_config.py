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
from synapse.util.module_loader import load_module

from ._base import Config, ConfigError

DEFAULT_USER_MAPPING_PROVIDER = "synapse.handlers.oidc_handler.JinjaOidcMappingProvider"


class OIDCConfig(Config):
    section = "oidc"

    def read_config(self, config, **kwargs):
        self.oidc_enabled = False

        oidc_config = config.get("oidc_config")

        if not oidc_config or not oidc_config.get("enabled", False):
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
        self.oidc_client_auth_method = oidc_config.get(
            "client_auth_method", "client_secret_basic"
        )
        self.oidc_scopes = oidc_config.get("scopes", ["openid"])
        self.oidc_authorization_endpoint = oidc_config.get("authorization_endpoint")
        self.oidc_token_endpoint = oidc_config.get("token_endpoint")
        self.oidc_userinfo_endpoint = oidc_config.get("userinfo_endpoint")
        self.oidc_jwks_uri = oidc_config.get("jwks_uri")
        self.oidc_subject_claim = oidc_config.get("subject_claim", "sub")
        self.oidc_skip_verification = oidc_config.get("skip_verification", False)

        ump_config = oidc_config.get("user_mapping_provider", {})
        ump_config.setdefault("module", DEFAULT_USER_MAPPING_PROVIDER)
        ump_config.setdefault("config", {})

        (
            self.oidc_user_mapping_provider_class,
            self.oidc_user_mapping_provider_config,
        ) = load_module(ump_config)

        # Ensure loaded user mapping module has defined all necessary methods
        required_methods = [
            "get_remote_user_id",
            "map_user_attributes",
        ]
        missing_methods = [
            method
            for method in required_methods
            if not hasattr(self.oidc_user_mapping_provider_class, method)
        ]
        if missing_methods:
            raise ConfigError(
                "Class specified by oidc_config."
                "user_mapping_provider.module is missing required "
                "methods: %s" % (", ".join(missing_methods),)
            )

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

            # auth method to use when exchanging the token.
            # Valid values are "client_secret_basic" (default), "client_secret_post" and "none".
            #
            #client_auth_method: "client_auth_basic"

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

            # skip metadata verification. Defaults to false.
            # Use this if you are connecting to a provider that is not OpenID Connect compliant.
            # Avoid this in production.
            #
            #skip_verification: false


            # An external module can be provided here as a custom solution to mapping
            # attributes returned from a OIDC provider onto a matrix user.
            #
            user_mapping_provider:
              # The custom module's class. Uncomment to use a custom module.
              # Default is {mapping_provider!r}.
              #
              #module: mapping_provider.OidcMappingProvider

              # Custom configuration values for the module. Below options are intended
              # for the built-in provider, they should be changed if using a custom
              # module. This section will be passed as a Python dictionary to the
              # module's `parse_config` method.
              #
              # Below is the config of the default mapping provider, based on Jinja2
              # templates. Those templates are used to render user attributes, where the
              # userinfo object is available through the `user` variable.
              #
              config:
                # name of the claim containing a unique identifier for the user.
                # Defaults to `sub`, which OpenID Connect compliant providers should provide.
                #
                #subject_claim: "sub"

                # Jinja2 template for the localpart of the MXID
                #
                localpart_template: "{{{{ user.preferred_username }}}}"

                # Jinja2 template for the display name to set on first login. Optional.
                #
                #display_name_template: "{{{{ user.given_name }}}} {{{{ user.last_name }}}}"
        """.format(
            mapping_provider=DEFAULT_USER_MAPPING_PROVIDER
        )
