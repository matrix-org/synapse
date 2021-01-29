# -*- coding: utf-8 -*-
# Copyright 2020 Quentin Gliech
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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

import string
from typing import Iterable, Optional, Tuple, Type

import attr

from synapse.config._util import validate_config
from synapse.python_dependencies import DependencyException, check_requirements
from synapse.types import Collection, JsonDict
from synapse.util.module_loader import load_module
from synapse.util.stringutils import parse_and_validate_mxc_uri

from ._base import Config, ConfigError

DEFAULT_USER_MAPPING_PROVIDER = "synapse.handlers.oidc_handler.JinjaOidcMappingProvider"


class OIDCConfig(Config):
    section = "oidc"

    def read_config(self, config, **kwargs):
        self.oidc_providers = tuple(_parse_oidc_provider_configs(config))
        if not self.oidc_providers:
            return

        try:
            check_requirements("oidc")
        except DependencyException as e:
            raise ConfigError(e.message) from e

        public_baseurl = self.public_baseurl
        self.oidc_callback_url = public_baseurl + "_synapse/oidc/callback"

    @property
    def oidc_enabled(self) -> bool:
        # OIDC is enabled if we have a provider
        return bool(self.oidc_providers)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # List of OpenID Connect (OIDC) / OAuth 2.0 identity providers, for registration
        # and login.
        #
        # Options for each entry include:
        #
        #   idp_id: a unique identifier for this identity provider. Used internally
        #       by Synapse; should be a single word such as 'github'.
        #
        #       Note that, if this is changed, users authenticating via that provider
        #       will no longer be recognised as the same user!
        #
        #   idp_name: A user-facing name for this identity provider, which is used to
        #       offer the user a choice of login mechanisms.
        #
        #   idp_icon: An optional icon for this identity provider, which is presented
        #       by identity picker pages. If given, must be an MXC URI of the format
        #       mxc://<server-name>/<media-id>. (An easy way to obtain such an MXC URI
        #       is to upload an image to an (unencrypted) room and then copy the "url"
        #       from the source of the event.)
        #
        #   discover: set to 'false' to disable the use of the OIDC discovery mechanism
        #       to discover endpoints. Defaults to true.
        #
        #   issuer: Required. The OIDC issuer. Used to validate tokens and (if discovery
        #       is enabled) to discover the provider's endpoints.
        #
        #   client_id: Required. oauth2 client id to use.
        #
        #   client_secret: Required. oauth2 client secret to use.
        #
        #   client_auth_method: auth method to use when exchanging the token. Valid
        #       values are 'client_secret_basic' (default), 'client_secret_post' and
        #       'none'.
        #
        #   scopes: list of scopes to request. This should normally include the "openid"
        #       scope. Defaults to ["openid"].
        #
        #   authorization_endpoint: the oauth2 authorization endpoint. Required if
        #       provider discovery is disabled.
        #
        #   token_endpoint: the oauth2 token endpoint. Required if provider discovery is
        #       disabled.
        #
        #   userinfo_endpoint: the OIDC userinfo endpoint. Required if discovery is
        #       disabled and the 'openid' scope is not requested.
        #
        #   jwks_uri: URI where to fetch the JWKS. Required if discovery is disabled and
        #       the 'openid' scope is used.
        #
        #   skip_verification: set to 'true' to skip metadata verification. Use this if
        #       you are connecting to a provider that is not OpenID Connect compliant.
        #       Defaults to false. Avoid this in production.
        #
        #   user_profile_method: Whether to fetch the user profile from the userinfo
        #       endpoint. Valid values are: 'auto' or 'userinfo_endpoint'.
        #
        #       Defaults to 'auto', which fetches the userinfo endpoint if 'openid' is
        #       included in 'scopes'. Set to 'userinfo_endpoint' to always fetch the
        #       userinfo endpoint.
        #
        #   allow_existing_users: set to 'true' to allow a user logging in via OIDC to
        #       match a pre-existing account instead of failing. This could be used if
        #       switching from password logins to OIDC. Defaults to false.
        #
        #   user_mapping_provider: Configuration for how attributes returned from a OIDC
        #       provider are mapped onto a matrix user. This setting has the following
        #       sub-properties:
        #
        #       module: The class name of a custom mapping module. Default is
        #           {mapping_provider!r}.
        #           See https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md#openid-mapping-providers
        #           for information on implementing a custom mapping provider.
        #
        #       config: Configuration for the mapping provider module. This section will
        #           be passed as a Python dictionary to the user mapping provider
        #           module's `parse_config` method.
        #
        #           For the default provider, the following settings are available:
        #
        #             sub: name of the claim containing a unique identifier for the
        #                 user. Defaults to 'sub', which OpenID Connect compliant
        #                 providers should provide.
        #
        #             localpart_template: Jinja2 template for the localpart of the MXID.
        #                 If this is not set, the user will be prompted to choose their
        #                 own username.
        #
        #             display_name_template: Jinja2 template for the display name to set
        #                 on first login. If unset, no displayname will be set.
        #
        #             extra_attributes: a map of Jinja2 templates for extra attributes
        #                 to send back to the client during login.
        #                 Note that these are non-standard and clients will ignore them
        #                 without modifications.
        #
        #           When rendering, the Jinja2 templates are given a 'user' variable,
        #           which is set to the claims returned by the UserInfo Endpoint and/or
        #           in the ID Token.
        #
        # See https://github.com/matrix-org/synapse/blob/master/docs/openid.md
        # for information on how to configure these options.
        #
        # For backwards compatibility, it is also possible to configure a single OIDC
        # provider via an 'oidc_config' setting. This is now deprecated and admins are
        # advised to migrate to the 'oidc_providers' format. (When doing that migration,
        # use 'oidc' for the idp_id to ensure that existing users continue to be
        # recognised.)
        #
        oidc_providers:
          # Generic example
          #
          #- idp_id: my_idp
          #  idp_name: "My OpenID provider"
          #  idp_icon: "mxc://example.com/mediaid"
          #  discover: false
          #  issuer: "https://accounts.example.com/"
          #  client_id: "provided-by-your-issuer"
          #  client_secret: "provided-by-your-issuer"
          #  client_auth_method: client_secret_post
          #  scopes: ["openid", "profile"]
          #  authorization_endpoint: "https://accounts.example.com/oauth2/auth"
          #  token_endpoint: "https://accounts.example.com/oauth2/token"
          #  userinfo_endpoint: "https://accounts.example.com/userinfo"
          #  jwks_uri: "https://accounts.example.com/.well-known/jwks.json"
          #  skip_verification: true

          # For use with Keycloak
          #
          #- idp_id: keycloak
          #  idp_name: Keycloak
          #  issuer: "https://127.0.0.1:8443/auth/realms/my_realm_name"
          #  client_id: "synapse"
          #  client_secret: "copy secret generated in Keycloak UI"
          #  scopes: ["openid", "profile"]

          # For use with Github
          #
          #- idp_id: github
          #  idp_name: Github
          #  discover: false
          #  issuer: "https://github.com/"
          #  client_id: "your-client-id" # TO BE FILLED
          #  client_secret: "your-client-secret" # TO BE FILLED
          #  authorization_endpoint: "https://github.com/login/oauth/authorize"
          #  token_endpoint: "https://github.com/login/oauth/access_token"
          #  userinfo_endpoint: "https://api.github.com/user"
          #  scopes: ["read:user"]
          #  user_mapping_provider:
          #    config:
          #      subject_claim: "id"
          #      localpart_template: "{{ user.login }}"
          #      display_name_template: "{{ user.name }}"
        """.format(
            mapping_provider=DEFAULT_USER_MAPPING_PROVIDER
        )


# jsonschema definition of the configuration settings for an oidc identity provider
OIDC_PROVIDER_CONFIG_SCHEMA = {
    "type": "object",
    "required": ["issuer", "client_id", "client_secret"],
    "properties": {
        # TODO: fix the maxLength here depending on what MSC2528 decides
        #   remember that we prefix the ID given here with `oidc-`
        "idp_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "idp_name": {"type": "string"},
        "idp_icon": {"type": "string"},
        "discover": {"type": "boolean"},
        "issuer": {"type": "string"},
        "client_id": {"type": "string"},
        "client_secret": {"type": "string"},
        "client_auth_method": {
            "type": "string",
            # the following list is the same as the keys of
            # authlib.oauth2.auth.ClientAuth.DEFAULT_AUTH_METHODS. We inline it
            # to avoid importing authlib here.
            "enum": ["client_secret_basic", "client_secret_post", "none"],
        },
        "scopes": {"type": "array", "items": {"type": "string"}},
        "authorization_endpoint": {"type": "string"},
        "token_endpoint": {"type": "string"},
        "userinfo_endpoint": {"type": "string"},
        "jwks_uri": {"type": "string"},
        "skip_verification": {"type": "boolean"},
        "user_profile_method": {
            "type": "string",
            "enum": ["auto", "userinfo_endpoint"],
        },
        "allow_existing_users": {"type": "boolean"},
        "user_mapping_provider": {"type": ["object", "null"]},
    },
}

# the same as OIDC_PROVIDER_CONFIG_SCHEMA, but with compulsory idp_id and idp_name
OIDC_PROVIDER_CONFIG_WITH_ID_SCHEMA = {
    "allOf": [OIDC_PROVIDER_CONFIG_SCHEMA, {"required": ["idp_id", "idp_name"]}]
}


# the `oidc_providers` list can either be None (as it is in the default config), or
# a list of provider configs, each of which requires an explicit ID and name.
OIDC_PROVIDER_LIST_SCHEMA = {
    "oneOf": [
        {"type": "null"},
        {"type": "array", "items": OIDC_PROVIDER_CONFIG_WITH_ID_SCHEMA},
    ]
}

# the `oidc_config` setting can either be None (which it used to be in the default
# config), or an object. If an object, it is ignored unless it has an "enabled: True"
# property.
#
# It's *possible* to represent this with jsonschema, but the resultant errors aren't
# particularly clear, so we just check for either an object or a null here, and do
# additional checks in the code.
OIDC_CONFIG_SCHEMA = {"oneOf": [{"type": "null"}, {"type": "object"}]}

# the top-level schema can contain an "oidc_config" and/or an "oidc_providers".
MAIN_CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "oidc_config": OIDC_CONFIG_SCHEMA,
        "oidc_providers": OIDC_PROVIDER_LIST_SCHEMA,
    },
}


def _parse_oidc_provider_configs(config: JsonDict) -> Iterable["OidcProviderConfig"]:
    """extract and parse the OIDC provider configs from the config dict

    The configuration may contain either a single `oidc_config` object with an
    `enabled: True` property, or a list of provider configurations under
    `oidc_providers`, *or both*.

    Returns a generator which yields the OidcProviderConfig objects
    """
    validate_config(MAIN_CONFIG_SCHEMA, config, ())

    for i, p in enumerate(config.get("oidc_providers") or []):
        yield _parse_oidc_config_dict(p, ("oidc_providers", "<item %i>" % (i,)))

    # for backwards-compatibility, it is also possible to provide a single "oidc_config"
    # object with an "enabled: True" property.
    oidc_config = config.get("oidc_config")
    if oidc_config and oidc_config.get("enabled", False):
        # MAIN_CONFIG_SCHEMA checks that `oidc_config` is an object, but not that
        # it matches OIDC_PROVIDER_CONFIG_SCHEMA (see the comments on OIDC_CONFIG_SCHEMA
        # above), so now we need to validate it.
        validate_config(OIDC_PROVIDER_CONFIG_SCHEMA, oidc_config, ("oidc_config",))
        yield _parse_oidc_config_dict(oidc_config, ("oidc_config",))


def _parse_oidc_config_dict(
    oidc_config: JsonDict, config_path: Tuple[str, ...]
) -> "OidcProviderConfig":
    """Take the configuration dict and parse it into an OidcProviderConfig

    Raises:
        ConfigError if the configuration is malformed.
    """
    ump_config = oidc_config.get("user_mapping_provider", {})
    ump_config.setdefault("module", DEFAULT_USER_MAPPING_PROVIDER)
    ump_config.setdefault("config", {})

    (user_mapping_provider_class, user_mapping_provider_config,) = load_module(
        ump_config, config_path + ("user_mapping_provider",)
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
            "Class %s is missing required "
            "methods: %s" % (user_mapping_provider_class, ", ".join(missing_methods),),
            config_path + ("user_mapping_provider", "module"),
        )

    # MSC2858 will apply certain limits in what can be used as an IdP id, so let's
    # enforce those limits now.
    # TODO: factor out this stuff to a generic function
    idp_id = oidc_config.get("idp_id", "oidc")

    # TODO: update this validity check based on what MSC2858 decides.
    valid_idp_chars = set(string.ascii_lowercase + string.digits + "-._")

    if any(c not in valid_idp_chars for c in idp_id):
        raise ConfigError(
            'idp_id may only contain a-z, 0-9, "-", ".", "_"',
            config_path + ("idp_id",),
        )

    if idp_id[0] not in string.ascii_lowercase:
        raise ConfigError(
            "idp_id must start with a-z", config_path + ("idp_id",),
        )

    # prefix the given IDP with a prefix specific to the SSO mechanism, to avoid
    # clashes with other mechs (such as SAML, CAS).
    #
    # We allow "oidc" as an exception so that people migrating from old-style
    # "oidc_config" format (which has long used "oidc" as its idp_id) can migrate to
    # a new-style "oidc_providers" entry without changing the idp_id for their provider
    # (and thereby invalidating their user_external_ids data).

    if idp_id != "oidc":
        idp_id = "oidc-" + idp_id

    # MSC2858 also specifies that the idp_icon must be a valid MXC uri
    idp_icon = oidc_config.get("idp_icon")
    if idp_icon is not None:
        try:
            parse_and_validate_mxc_uri(idp_icon)
        except ValueError as e:
            raise ConfigError(
                "idp_icon must be a valid MXC URI", config_path + ("idp_icon",)
            ) from e

    return OidcProviderConfig(
        idp_id=idp_id,
        idp_name=oidc_config.get("idp_name", "OIDC"),
        idp_icon=idp_icon,
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


@attr.s(slots=True, frozen=True)
class OidcProviderConfig:
    # a unique identifier for this identity provider. Used in the 'user_external_ids'
    # table, as well as the query/path parameter used in the login protocol.
    idp_id = attr.ib(type=str)

    # user-facing name for this identity provider.
    idp_name = attr.ib(type=str)

    # Optional MXC URI for icon for this IdP.
    idp_icon = attr.ib(type=Optional[str])

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
