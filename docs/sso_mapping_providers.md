# SSO Mapping Providers

A mapping provider is a Python class (loaded via a Python module) that
works out how to map attributes of a SSO response to Matrix-specific
user attributes. Details such as user ID localpart, displayname, and even avatar
URLs are all things that can be mapped from talking to a SSO service.

As an example, a SSO service may return the email address
"john.smith@example.com" for a user, whereas Synapse will need to figure out how
to turn that into a displayname when creating a Matrix user for this individual.
It may choose `John Smith`, or `Smith, John [Example.com]` or any number of
variations. As each Synapse configuration may want something different, this is
where SAML mapping providers come into play.

SSO mapping providers are currently supported for OpenID and SAML SSO
configurations. Please see the details below for how to implement your own.

It is up to the mapping provider whether the user should be assigned a predefined
Matrix ID based on the SSO attributes, or if the user should be allowed to
choose their own username.

In the first case - where users are automatically allocated a Matrix ID - it is
the responsibility of the mapping provider to normalise the SSO attributes and
map them to a valid Matrix ID. The [specification for Matrix
IDs](https://spec.matrix.org/latest/appendices/#user-identifiers) has some
information about what is considered valid.

If the mapping provider does not assign a Matrix ID, then Synapse will
automatically serve an HTML page allowing the user to pick their own username.

External mapping providers are provided to Synapse in the form of an external
Python module. You can retrieve this module from [PyPI](https://pypi.org) or elsewhere,
but it must be importable via Synapse (e.g. it must be in the same virtualenv
as Synapse). The Synapse config is then modified to point to the mapping provider
(and optionally provide additional configuration for it).

## OpenID Mapping Providers

The OpenID mapping provider can be customized by editing the
[`oidc_providers.user_mapping_provider.module`](usage/configuration/config_documentation.md#oidc_providers)
config option.

`oidc_providers.user_mapping_provider.config` allows you to provide custom
configuration options to the module. Check with the module's documentation for
what options it provides (if any). The options listed by default are for the
user mapping provider built in to Synapse. If using a custom module, you should
comment these options out and use those specified by the module instead.

### Building a Custom OpenID Mapping Provider

A custom mapping provider must specify the following methods:

* `def __init__(self, parsed_config)`
   - Arguments:
     - `parsed_config` - A configuration object that is the return value of the
       `parse_config` method. You should set any configuration options needed by
       the module here.
* `def parse_config(config)`
    - This method should have the `@staticmethod` decoration.
    - Arguments:
        - `config` - A `dict` representing the parsed content of the
          `oidc_providers.user_mapping_provider.config` homeserver config option.
           Runs on homeserver startup. Providers should extract and validate
           any option values they need here.
    - Whatever is returned will be passed back to the user mapping provider module's
      `__init__` method during construction.
* `def get_remote_user_id(self, userinfo)`
    - Arguments:
      - `userinfo` - A `authlib.oidc.core.claims.UserInfo` object to extract user
                     information from.
    - This method must return a string, which is the unique, immutable identifier
      for the user. Commonly the `sub` claim of the response.
* `async def map_user_attributes(self, userinfo, token, failures)`
    - This method must be async.
    - Arguments:
      - `userinfo` - An [`authlib.oidc.core.claims.UserInfo`](https://docs.authlib.org/en/latest/specs/oidc.html#authlib.oidc.core.UserInfo)
                     object to extract user information from.
      - `token` - A dictionary which includes information necessary to make
                  further requests to the OpenID provider.
      - `failures` - An `int` that represents the amount of times the returned
                     mxid localpart mapping has failed.  This should be used
                     to create a deduplicated mxid localpart which should be
                     returned instead. For example, if this method returns
                     `john.doe` as the value of `localpart` in the returned
                     dict, and that is already taken on the homeserver, this
                     method will be called again with the same parameters but
                     with failures=1. The method should then return a different
                     `localpart` value, such as `john.doe1`.
    - Returns a dictionary with two keys:
      - `localpart`: A string, used to generate the Matrix ID. If this is
        `None`, the user is prompted to pick their own username. This is only used
        during a user's first login. Once a localpart has been associated with a
        remote user ID (see `get_remote_user_id`) it cannot be updated.
      - `confirm_localpart`: A boolean. If set to `True`, when a `localpart`
        string is returned from this method, Synapse will prompt the user to
        either accept this localpart or pick their own username. Otherwise this
        option has no effect. If omitted, defaults to `False`.
      - `display_name`: An optional string, the display name for the user.
      - `emails`: A list of strings, the email address(es) to associate with
        this user. If omitted, defaults to an empty list.
* `async def get_extra_attributes(self, userinfo, token)`
    - This method must be async.
    - Arguments:
      - `userinfo` - A `authlib.oidc.core.claims.UserInfo` object to extract user
                     information from.
      - `token` - A dictionary which includes information necessary to make
                  further requests to the OpenID provider.
    - Returns a dictionary that is suitable to be serialized to JSON. This
      will be returned as part of the response during a successful login.

      Note that care should be taken to not overwrite any of the parameters
      usually returned as part of the [login response](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3login).

### Default OpenID Mapping Provider

Synapse has a built-in OpenID mapping provider if a custom provider isn't
specified in the config. It is located at
[`synapse.handlers.oidc.JinjaOidcMappingProvider`](https://github.com/matrix-org/synapse/blob/develop/synapse/handlers/oidc.py).

## SAML Mapping Providers

The SAML mapping provider can be customized by editing the
[`saml2_config.user_mapping_provider.module`](usage/configuration/config_documentation.md#saml2_config)
config option.

`saml2_config.user_mapping_provider.config` allows you to provide custom
configuration options to the module. Check with the module's documentation for
what options it provides (if any). The options listed by default are for the
user mapping provider built in to Synapse. If using a custom module, you should
comment these options out and use those specified by the module instead.

### Building a Custom SAML Mapping Provider

A custom mapping provider must specify the following methods:

* `def __init__(self, parsed_config, module_api)`
   - Arguments:
     - `parsed_config` - A configuration object that is the return value of the
       `parse_config` method. You should set any configuration options needed by
       the module here.
     - `module_api` - a `synapse.module_api.ModuleApi` object which provides the
       stable API available for extension modules.
* `def parse_config(config)`
    - **This method should have the `@staticmethod` decoration.**
    - Arguments:
        - `config` - A `dict` representing the parsed content of the
          `saml_config.user_mapping_provider.config` homeserver config option.
           Runs on homeserver startup. Providers should extract and validate
           any option values they need here.
    - Whatever is returned will be passed back to the user mapping provider module's
      `__init__` method during construction.
* `def get_saml_attributes(config)`
    - **This method should have the `@staticmethod` decoration.**
    - Arguments:
        - `config` - A object resulting from a call to `parse_config`.
    - Returns a tuple of two sets. The first set equates to the SAML auth
      response attributes that are required for the module to function, whereas
      the second set consists of those attributes which can be used if available,
      but are not necessary.
* `def get_remote_user_id(self, saml_response, client_redirect_url)`
    - Arguments:
      - `saml_response` - A `saml2.response.AuthnResponse` object to extract user
                          information from.
      - `client_redirect_url` - A string, the URL that the client will be
                                redirected to.
    - This method must return a string, which is the unique, immutable identifier
      for the user. Commonly the `uid` claim of the response.
* `def saml_response_to_user_attributes(self, saml_response, failures, client_redirect_url)`
    - Arguments:
      - `saml_response` - A `saml2.response.AuthnResponse` object to extract user
                          information from.
      - `failures` - An `int` that represents the amount of times the returned
                     mxid localpart mapping has failed.  This should be used
                     to create a deduplicated mxid localpart which should be
                     returned instead. For example, if this method returns
                     `john.doe` as the value of `mxid_localpart` in the returned
                     dict, and that is already taken on the homeserver, this
                     method will be called again with the same parameters but
                     with failures=1. The method should then return a different
                     `mxid_localpart` value, such as `john.doe1`.
      - `client_redirect_url` - A string, the URL that the client will be
                                redirected to.
    - This method must return a dictionary, which will then be used by Synapse
      to build a new user. The following keys are allowed:
       * `mxid_localpart` - A string, the mxid localpart of the new user. If this is
         `None`, the user is prompted to pick their own username. This is only used
         during a user's first login. Once a localpart has been associated with a
         remote user ID (see `get_remote_user_id`) it cannot be updated.
       * `displayname` - The displayname of the new user. If not provided, will default to
                         the value of `mxid_localpart`.
       * `emails` - A list of emails for the new user. If not provided, will
                    default to an empty list.

       Alternatively it can raise a `synapse.api.errors.RedirectException` to
       redirect the user to another page. This is useful to prompt the user for
       additional information, e.g. if you want them to provide their own username.
       It is the responsibility of the mapping provider to either redirect back
       to `client_redirect_url` (including any additional information) or to
       complete registration using methods from the `ModuleApi`.

### Default SAML Mapping Provider

Synapse has a built-in SAML mapping provider if a custom provider isn't
specified in the config. It is located at
[`synapse.handlers.saml.DefaultSamlMappingProvider`](https://github.com/matrix-org/synapse/blob/develop/synapse/handlers/saml.py).
