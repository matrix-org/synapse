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

from collections import Counter
from typing import Collection, Iterable, List, Mapping, Optional, Tuple, Type

import attr

from synapse.config._util import validate_config
from synapse.config.sso import SsoAttributeRequirement
from synapse.python_dependencies import DependencyException, check_requirements
from synapse.types import JsonDict
from synapse.util.module_loader import load_module
from synapse.util.stringutils import parse_and_validate_mxc_uri

from ._base import Config, ConfigError, read_file

DEFAULT_USER_MAPPING_PROVIDER = "synapse.handlers.oidc.JinjaOidcMappingProvider"
# The module that JinjaOidcMappingProvider is in was renamed, we want to
# transparently handle both the same.
LEGACY_USER_MAPPING_PROVIDER = "synapse.handlers.oidc_handler.JinjaOidcMappingProvider"


class OIDCConfig(Config):
    section = "oidc"

    def read_config(self, config, **kwargs):
        self.oidc_providers = tuple(_parse_oidc_provider_configs(config))
        if not self.oidc_providers:
            return

        try:
            check_requirements("oidc")
        except DependencyException as e:
            raise ConfigError(
                e.message  # noqa: B306, DependencyException.message is a property
            ) from e

        # check we don't have any duplicate idp_ids now. (The SSO handler will also
        # check for duplicates when the REST listeners get registered, but that happens
        # after synapse has forked so doesn't give nice errors.)
        c = Counter([i.idp_id for i in self.oidc_providers])
        for idp_id, count in c.items():
            if count > 1:
                raise ConfigError(
                    "Multiple OIDC providers have the idp_id %r." % idp_id
                )

        public_baseurl = self.public_baseurl
        if public_baseurl is None:
            raise ConfigError("oidc_config requires a public_baseurl to be set")
        self.oidc_callback_url = public_baseurl + "_synapse/client/oidc/callback"

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
        #       (Use "oidc" here if you are migrating from an old "oidc_config"
        #       configuration.)
        #
        #   idp_name: A user-facing name for this identity provider, which is used to
        #       offer the user a choice of login mechanisms.
        #
        #   idp_icon: An optional icon for this identity provider, which is presented
        #       by clients and Synapse's own IdP picker page. If given, must be an
        #       MXC URI of the format mxc://<server-name>/<media-id>. (An easy way to
        #       obtain such an MXC URI is to upload an image to an (unencrypted) room
        #       and then copy the "url" from the source of the event.)
        #
        #   idp_brand: An optional brand for this identity provider, allowing clients
        #       to style the login flow according to the identity provider in question.
        #       See the spec for possible options here.
        #
        #   discover: set to 'false' to disable the use of the OIDC discovery mechanism
        #       to discover endpoints. Defaults to true.
        #
        #   issuer: Required. The OIDC issuer. Used to validate tokens and (if discovery
        #       is enabled) to discover the provider's endpoints.
        #
        #   client_id: Required. oauth2 client id to use.
        #
        #   client_secret: oauth2 client secret to use. May be omitted if
        #        client_secret_jwt_key is given, or if client_auth_method is 'none'.
        #
        #   client_secret_jwt_key: Alternative to client_secret: details of a key used
        #      to create a JSON Web Token to be used as an OAuth2 client secret. If
        #      given, must be a dictionary with the following properties:
        #
        #          key: a pem-encoded signing key. Must be a suitable key for the
        #              algorithm specified. Required unless 'key_file' is given.
        #
        #          key_file: the path to file containing a pem-encoded signing key file.
        #              Required unless 'key' is given.
        #
        #          jwt_header: a dictionary giving properties to include in the JWT
        #              header. Must include the key 'alg', giving the algorithm used to
        #              sign the JWT, such as "ES256", using the JWA identifiers in
        #              RFC7518.
        #
        #          jwt_payload: an optional dictionary giving properties to include in
        #              the JWT payload. Normally this should include an 'iss' key.
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
        #           See https://matrix-org.github.io/synapse/latest/sso_mapping_providers.html#openid-mapping-providers
        #           for information on implementing a custom mapping provider.
        #
        #       config: Configuration for the mapping provider module. This section will
        #           be passed as a Python dictionary to the user mapping provider
        #           module's `parse_config` method.
        #
        #           For the default provider, the following settings are available:
        #
        #             subject_claim: name of the claim containing a unique identifier
        #                 for the user. Defaults to 'sub', which OpenID Connect
        #                 compliant providers should provide.
        #
        #             localpart_template: Jinja2 template for the localpart of the MXID.
        #                 If this is not set, the user will be prompted to choose their
        #                 own username (see 'sso_auth_account_details.html' in the 'sso'
        #                 section of this file).
        #
        #             display_name_template: Jinja2 template for the display name to set
        #                 on first login. If unset, no displayname will be set.
        #
        #             email_template: Jinja2 template for the email address of the user.
        #                 If unset, no email address will be added to the account.
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
        #   It is possible to configure Synapse to only allow logins if certain attributes
        #   match particular values in the OIDC userinfo. The requirements can be listed under
        #   `attribute_requirements` as shown below. All of the listed attributes must
        #   match for the login to be permitted. Additional attributes can be added to
        #   userinfo by expanding the `scopes` section of the OIDC config to retrieve
        #   additional information from the OIDC provider.
        #
        #   If the OIDC claim is a list, then the attribute must match any value in the list.
        #   Otherwise, it must exactly match the value of the claim. Using the example
        #   below, the `family_name` claim MUST be "Stephensson", but the `groups`
        #   claim MUST contain "admin".
        #
        #   attribute_requirements:
        #     - attribute: family_name
        #       value: "Stephensson"
        #     - attribute: groups
        #       value: "admin"
        #
        # See https://matrix-org.github.io/synapse/latest/openid.html
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
          #  user_mapping_provider:
          #    config:
          #      subject_claim: "id"
          #      localpart_template: "{{{{ user.login }}}}"
          #      display_name_template: "{{{{ user.name }}}}"
          #      email_template: "{{{{ user.email }}}}"
          #  attribute_requirements:
          #    - attribute: userGroup
          #      value: "synapseUsers"
        """.format(
            mapping_provider=DEFAULT_USER_MAPPING_PROVIDER
        )


# jsonschema definition of the configuration settings for an oidc identity provider
OIDC_PROVIDER_CONFIG_SCHEMA = {
    "type": "object",
    "required": ["issuer", "client_id"],
    "properties": {
        "idp_id": {
            "type": "string",
            "minLength": 1,
            # MSC2858 allows a maxlen of 255, but we prefix with "oidc-"
            "maxLength": 250,
            "pattern": "^[A-Za-z0-9._~-]+$",
        },
        "idp_name": {"type": "string"},
        "idp_icon": {"type": "string"},
        "idp_brand": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "pattern": "^[a-z][a-z0-9_.-]*$",
        },
        "idp_unstable_brand": {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "pattern": "^[a-z][a-z0-9_.-]*$",
        },
        "discover": {"type": "boolean"},
        "issuer": {"type": "string"},
        "client_id": {"type": "string"},
        "client_secret": {"type": "string"},
        "client_secret_jwt_key": {
            "type": "object",
            "required": ["jwt_header"],
            "oneOf": [
                {"required": ["key"]},
                {"required": ["key_file"]},
            ],
            "properties": {
                "key": {"type": "string"},
                "key_file": {"type": "string"},
                "jwt_header": {
                    "type": "object",
                    "required": ["alg"],
                    "properties": {
                        "alg": {"type": "string"},
                    },
                    "additionalProperties": {"type": "string"},
                },
                "jwt_payload": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
            },
        },
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
        "attribute_requirements": {
            "type": "array",
            "items": SsoAttributeRequirement.JSON_SCHEMA,
        },
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
    if ump_config.get("module") == LEGACY_USER_MAPPING_PROVIDER:
        ump_config["module"] = DEFAULT_USER_MAPPING_PROVIDER
    ump_config.setdefault("config", {})

    (
        user_mapping_provider_class,
        user_mapping_provider_config,
    ) = load_module(ump_config, config_path + ("user_mapping_provider",))

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
            "methods: %s"
            % (
                user_mapping_provider_class,
                ", ".join(missing_methods),
            ),
            config_path + ("user_mapping_provider", "module"),
        )

    idp_id = oidc_config.get("idp_id", "oidc")

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

    client_secret_jwt_key_config = oidc_config.get("client_secret_jwt_key")
    client_secret_jwt_key = None  # type: Optional[OidcProviderClientSecretJwtKey]
    if client_secret_jwt_key_config is not None:
        keyfile = client_secret_jwt_key_config.get("key_file")
        if keyfile:
            key = read_file(keyfile, config_path + ("client_secret_jwt_key",))
        else:
            key = client_secret_jwt_key_config["key"]
        client_secret_jwt_key = OidcProviderClientSecretJwtKey(
            key=key,
            jwt_header=client_secret_jwt_key_config["jwt_header"],
            jwt_payload=client_secret_jwt_key_config.get("jwt_payload", {}),
        )
    # parse attribute_requirements from config (list of dicts) into a list of SsoAttributeRequirement
    attribute_requirements = [
        SsoAttributeRequirement(**x)
        for x in oidc_config.get("attribute_requirements", [])
    ]

    return OidcProviderConfig(
        idp_id=idp_id,
        idp_name=oidc_config.get("idp_name", "OIDC"),
        idp_icon=idp_icon,
        idp_brand=oidc_config.get("idp_brand"),
        unstable_idp_brand=oidc_config.get("unstable_idp_brand"),
        discover=oidc_config.get("discover", True),
        issuer=oidc_config["issuer"],
        client_id=oidc_config["client_id"],
        client_secret=oidc_config.get("client_secret"),
        client_secret_jwt_key=client_secret_jwt_key,
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
        attribute_requirements=attribute_requirements,
    )


@attr.s(slots=True, frozen=True)
class OidcProviderClientSecretJwtKey:
    # a pem-encoded signing key
    key = attr.ib(type=str)

    # properties to include in the JWT header
    jwt_header = attr.ib(type=Mapping[str, str])

    # properties to include in the JWT payload.
    jwt_payload = attr.ib(type=Mapping[str, str])


@attr.s(slots=True, frozen=True)
class OidcProviderConfig:
    # a unique identifier for this identity provider. Used in the 'user_external_ids'
    # table, as well as the query/path parameter used in the login protocol.
    idp_id = attr.ib(type=str)

    # user-facing name for this identity provider.
    idp_name = attr.ib(type=str)

    # Optional MXC URI for icon for this IdP.
    idp_icon = attr.ib(type=Optional[str])

    # Optional brand identifier for this IdP.
    idp_brand = attr.ib(type=Optional[str])

    # Optional brand identifier for the unstable API (see MSC2858).
    unstable_idp_brand = attr.ib(type=Optional[str])

    # whether the OIDC discovery mechanism is used to discover endpoints
    discover = attr.ib(type=bool)

    # the OIDC issuer. Used to validate tokens and (if discovery is enabled) to
    # discover the provider's endpoints.
    issuer = attr.ib(type=str)

    # oauth2 client id to use
    client_id = attr.ib(type=str)

    # oauth2 client secret to use. if `None`, use client_secret_jwt_key to generate
    # a secret.
    client_secret = attr.ib(type=Optional[str])

    # key to use to construct a JWT to use as a client secret. May be `None` if
    # `client_secret` is set.
    client_secret_jwt_key = attr.ib(type=Optional[OidcProviderClientSecretJwtKey])

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

    # required attributes to require in userinfo to allow login/registration
    attribute_requirements = attr.ib(type=List[SsoAttributeRequirement])
