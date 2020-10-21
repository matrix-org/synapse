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
        self.oidc_skip_verification = oidc_config.get("skip_verification", False)
        self.oidc_allow_existing_users = oidc_config.get("allow_existing_users", False)

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
        # OpenID Connect integration. The following settings can be used to make Synapse
        # use an OpenID Connect Provider for authentication, instead of its internal
        # password database.
        #
        # See https://github.com/matrix-org/synapse/blob/master/docs/openid.md.
        #
        oidc_config:
          # Uncomment the following to enable authorization against an OpenID Connect
          # server. Defaults to false.
          #
          #enabled: true

          # Uncomment the following to disable use of the OIDC discovery mechanism to
          # discover endpoints. Defaults to true.
          #
          #discover: false

          # the OIDC issuer. Used to validate tokens and (if discovery is enabled) to
          # discover the provider's endpoints.
          #
          # Required if 'enabled' is true.
          #
          #issuer: "https://accounts.example.com/"

          # oauth2 client id to use.
          #
          # Required if 'enabled' is true.
          #
          #client_id: "provided-by-your-issuer"

          # oauth2 client secret to use.
          #
          # Required if 'enabled' is true.
          #
          #client_secret: "provided-by-your-issuer"

          # auth method to use when exchanging the token.
          # Valid values are 'client_secret_basic' (default), 'client_secret_post' and
          # 'none'.
          #
          #client_auth_method: client_secret_post

          # list of scopes to request. This should normally include the "openid" scope.
          # Defaults to ["openid"].
          #
          #scopes: ["openid", "profile"]

          # the oauth2 authorization endpoint. Required if provider discovery is disabled.
          #
          #authorization_endpoint: "https://accounts.example.com/oauth2/auth"

          # the oauth2 token endpoint. Required if provider discovery is disabled.
          #
          #token_endpoint: "https://accounts.example.com/oauth2/token"

          # the OIDC userinfo endpoint. Required if discovery is disabled and the
          # "openid" scope is not requested.
          #
          #userinfo_endpoint: "https://accounts.example.com/userinfo"

          # URI where to fetch the JWKS. Required if discovery is disabled and the
          # "openid" scope is used.
          #
          #jwks_uri: "https://accounts.example.com/.well-known/jwks.json"

          # Uncomment to skip metadata verification. Defaults to false.
          #
          # Use this if you are connecting to a provider that is not OpenID Connect
          # compliant.
          # Avoid this in production.
          #
          #skip_verification: true

          # Uncomment to allow a user logging in via OIDC to match a pre-existing account instead
          # of failing. This could be used if switching from password logins to OIDC. Defaults to false.
          #
          #allow_existing_users: true

          # An external module can be provided here as a custom solution to mapping
          # attributes returned from a OIDC provider onto a matrix user.
          #
          user_mapping_provider:
            # The custom module's class. Uncomment to use a custom module.
            # Default is {mapping_provider!r}.
            #
            # See https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md#openid-mapping-providers
            # for information on implementing a custom mapping provider.
            #
            #module: mapping_provider.OidcMappingProvider

            # Custom configuration values for the module. This section will be passed as
            # a Python dictionary to the user mapping provider module's `parse_config`
            # method.
            #
            # The examples below are intended for the default provider: they should be
            # changed if using a custom provider.
            #
            config:
              # name of the claim containing a unique identifier for the user.
              # Defaults to `sub`, which OpenID Connect compliant providers should provide.
              #
              #subject_claim: "sub"

              # Jinja2 template for the localpart of the MXID.
              #
              # When rendering, this template is given the following variables:
              #   * user: The claims returned by the UserInfo Endpoint and/or in the ID
              #     Token
              #
              # This must be configured if using the default mapping provider.
              #
              localpart_template: "{{{{ user.preferred_username }}}}"

              # Jinja2 template for the display name to set on first login.
              #
              # If unset, no displayname will be set.
              #
              #display_name_template: "{{{{ user.given_name }}}} {{{{ user.last_name }}}}"

              # Jinja2 templates for extra attributes to send back to the client during
              # login.
              #
              # Note that these are non-standard and clients will ignore them without modifications.
              #
              #extra_attributes:
                #birthdate: "{{{{ user.birthdate }}}}"
        """.format(
            mapping_provider=DEFAULT_USER_MAPPING_PROVIDER
        )
