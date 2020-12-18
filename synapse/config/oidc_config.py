# -*- coding: utf-8 -*-
# Copyright 2020 Quentin Gliech
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

from typing import Optional, Type

import attr

from synapse.python_dependencies import DependencyException, check_requirements
from synapse.types import Collection, JsonDict
from synapse.util.module_loader import load_module

from ._base import Config, ConfigError

DEFAULT_USER_MAPPING_PROVIDER = "synapse.handlers.oidc_handler.JinjaOidcMappingProvider"


class OIDCConfig(Config):
    section = "oidc"

    def read_config(self, config, **kwargs):
        self.oidc_provider = None  # type: Optional[OidcProviderConfig]

        oidc_config = config.get("oidc_config")
        if oidc_config and oidc_config.get("enabled", False):
            self.oidc_provider = _parse_oidc_config_dict(oidc_config)

        if not self.oidc_provider:
            return

        try:
            check_requirements("oidc")
        except DependencyException as e:
            raise ConfigError(e.message) from e

        public_baseurl = self.public_baseurl
        if public_baseurl is None:
            raise ConfigError("oidc_config requires a public_baseurl to be set")
        self.oidc_callback_url = public_baseurl + "_synapse/oidc/callback"

    @property
    def oidc_enabled(self) -> bool:
        # OIDC is enabled if we have a provider
        return bool(self.oidc_provider)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # Enable OpenID Connect (OIDC) / OAuth 2.0 for registration and login.
        #
        # See https://github.com/matrix-org/synapse/blob/master/docs/openid.md
        # for some example configurations.
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

          # Whether to fetch the user profile from the userinfo endpoint. Valid
          # values are: "auto" or "userinfo_endpoint".
          #
          # Defaults to "auto", which fetches the userinfo endpoint if "openid" is included
          # in `scopes`. Uncomment the following to always fetch the userinfo endpoint.
          #
          #user_profile_method: "userinfo_endpoint"

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
              # If this is not set, the user will be prompted to choose their
              # own username.
              #
              #localpart_template: "{{{{ user.preferred_username }}}}"

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


def _parse_oidc_config_dict(oidc_config: JsonDict) -> "OidcProviderConfig":
    """Take the configuration dict and parse it into an OidcProviderConfig

    Raises:
        ConfigError if the configuration is malformed.
    """
    ump_config = oidc_config.get("user_mapping_provider", {})
    ump_config.setdefault("module", DEFAULT_USER_MAPPING_PROVIDER)
    ump_config.setdefault("config", {})

    (user_mapping_provider_class, user_mapping_provider_config,) = load_module(
        ump_config, ("oidc_config", "user_mapping_provider")
    )

    # Ensure loaded user mapping module has defined all necessary methods
    required_methods = [
        "get_remote_user_id",
        "map_user_attributes",
    ]
    missing_methods = [
        method
        for method in required_methods
        if not hasattr(user_mapping_provider_class, method)
    ]
    if missing_methods:
        raise ConfigError(
            "Class specified by oidc_config."
            "user_mapping_provider.module is missing required "
            "methods: %s" % (", ".join(missing_methods),)
        )

    return OidcProviderConfig(
        discover=oidc_config.get("discover", True),
        issuer=oidc_config["issuer"],
        client_id=oidc_config["client_id"],
        client_secret=oidc_config["client_secret"],
        client_auth_method=oidc_config.get("client_auth_method", "client_secret_basic"),
        scopes=oidc_config.get("scopes", ["openid"]),
        authorization_endpoint=oidc_config.get("authorization_endpoint"),
        token_endpoint=oidc_config.get("token_endpoint"),
        userinfo_endpoint=oidc_config.get("userinfo_endpoint"),
        jwks_uri=oidc_config.get("jwks_uri"),
        skip_verification=oidc_config.get("skip_verification", False),
        user_profile_method=oidc_config.get("user_profile_method", "auto"),
        allow_existing_users=oidc_config.get("allow_existing_users", False),
        user_mapping_provider_class=user_mapping_provider_class,
        user_mapping_provider_config=user_mapping_provider_config,
    )


@attr.s
class OidcProviderConfig:
    # whether the OIDC discovery mechanism is used to discover endpoints
    discover = attr.ib(type=bool)

    # the OIDC issuer. Used to validate tokens and (if discovery is enabled) to
    # discover the provider's endpoints.
    issuer = attr.ib(type=str)

    # oauth2 client id to use
    client_id = attr.ib(type=str)

    # oauth2 client secret to use
    client_secret = attr.ib(type=str)

    # auth method to use when exchanging the token.
    # Valid values are 'client_secret_basic', 'client_secret_post' and
    # 'none'.
    client_auth_method = attr.ib(type=str)

    # list of scopes to request
    scopes = attr.ib(type=Collection[str])

    # the oauth2 authorization endpoint. Required if discovery is disabled.
    authorization_endpoint = attr.ib(type=Optional[str])

    # the oauth2 token endpoint. Required if discovery is disabled.
    token_endpoint = attr.ib(type=Optional[str])

    # the OIDC userinfo endpoint. Required if discovery is disabled and the
    # "openid" scope is not requested.
    userinfo_endpoint = attr.ib(type=Optional[str])

    # URI where to fetch the JWKS. Required if discovery is disabled and the
    # "openid" scope is used.
    jwks_uri = attr.ib(type=Optional[str])

    # Whether to skip metadata verification
    skip_verification = attr.ib(type=bool)

    # Whether to fetch the user profile from the userinfo endpoint. Valid
    # values are: "auto" or "userinfo_endpoint".
    user_profile_method = attr.ib(type=str)

    # whether to allow a user logging in via OIDC to match a pre-existing account
    # instead of failing
    allow_existing_users = attr.ib(type=bool)

    # the class of the user mapping provider
    user_mapping_provider_class = attr.ib(type=Type)

    # the config of the user mapping provider
    user_mapping_provider_config = attr.ib()
