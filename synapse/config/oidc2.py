from typing import Optional, Tuple, Any

from pydantic import BaseModel, StrictStr, validator, StrictBool
from synapse.config.validators import string_length_between, string_contains_characters


class OIDCProviderModel(BaseModel):
    """
    Notes on Pydantic:
    - I've used StrictStr because a plain `str` accepts integers and calls str() on them
    - I've factored out the validators here to demonstrate that we can avoid some duplication
      if there are common patterns. Otherwise one could use @validator("field_name") and
      define the validator function inline.
    """

    # a unique identifier for this identity provider. Used in the 'user_external_ids'
    # table, as well as the query/path parameter used in the login protocol.
    # TODO: this is optional in the old-style config, defaulting to "oidc".
    idp_id: StrictStr
    _idp_id_length = validator("idp_id")(string_length_between(1, 250))
    _idp_id_characters = validator("idp_id")(
        string_contains_characters("A-Za-z0-9._~-")
    )

    # user-facing name for this identity provider.
    # TODO: this is optional in the old-style config, defaulting to "OIDC".
    idp_name: StrictStr

    # Optional MXC URI for icon for this IdP.
    # TODO: validate that this is an MXC URI.
    idp_icon: Optional[StrictStr]

    # Optional brand identifier for this IdP.
    idp_brand: Optional[StrictStr]

    # whether the OIDC discovery mechanism is used to discover endpoints
    discover: StrictBool = True

    # the OIDC issuer. Used to validate tokens and (if discovery is enabled) to
    # discover the provider's endpoints.
    issuer: StrictStr

    # oauth2 client id to use
    client_id: StrictStr

    # oauth2 client secret to use. if `None`, use client_secret_jwt_key to generate
    # a secret.
    client_secret: Optional[StrictStr]

    # key to use to construct a JWT to use as a client secret. May be `None` if
    # `client_secret` is set.
    # TODO
    client_secret_jwt_key: Optional[Any]  # OidcProviderClientSecretJwtKey]

    # auth method to use when exchanging the token.
    # Valid values are 'client_secret_basic', 'client_secret_post' and
    # 'none'.
    client_auth_method: StrictStr = "client_secret_basic"

    # list of scopes to request
    scopes: Tuple[StrictStr, ...] = ("openid",)

    # the oauth2 authorization endpoint. Required if discovery is disabled.
    # TODO: required if discovery is disabled
    authorization_endpoint: Optional[StrictStr]

    # the oauth2 token endpoint. Required if discovery is disabled.
    # TODO: required if discovery is disabled
    token_endpoint: Optional[StrictStr]

    # the OIDC userinfo endpoint. Required if discovery is disabled and the
    # "openid" scope is not requested.
    # TODO: required if discovery is disabled and the openid scope isn't requested
    userinfo_endpoint: Optional[StrictStr]

    # URI where to fetch the JWKS. Required if discovery is disabled and the
    # "openid" scope is used.
    # TODO: required if discovery is disabled and the openid scope IS requested
    jwks_uri: Optional[StrictStr]

    # Whether to skip metadata verification
    skip_verification: StrictBool = False

    # Whether to fetch the user profile from the userinfo endpoint. Valid
    # values are: "auto" or "userinfo_endpoint".
    # TODO enum
    user_profile_method: StrictStr = "auto"

    # whether to allow a user logging in via OIDC to match a pre-existing account
    # instead of failing
    allow_existing_users: StrictBool = False

    # the class of the user mapping provider
    # TODO
    user_mapping_provider_class: Any  # TODO: Type

    # the config of the user mapping provider
    # TODO
    user_mapping_provider_config: Any

    # required attributes to require in userinfo to allow login/registration
    attribute_requirements: Tuple[
        Any, ...
    ] = tuple()  # TODO SsoAttributeRequirement] = tuple()
