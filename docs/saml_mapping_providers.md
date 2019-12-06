# SAML Mapping Providers

A SAML mapping provider is a Python class (loaded via a Python module) that
works out how to map attributes of a SAML response object to Matrix-specific
user attributes. Details such as user ID localpart, displayname, and even avatar
URLs are all things that can be mapped from talking to a SSO service.

As an example, a SSO service may return the email address
"john.smith@example.com" for a user, whereas Synapse will need to figure out how
to turn that into a displayname when creating a Matrix user for this individual.
It may choose `John Smith`, or `Smith, John [Example.com]` or any number of
variations. As each Synapse configuration may want something different, this is
where SAML mapping providers come into play.

## Enabling Providers

External mapping providers are provided to Synapse in the form of an external
Python module. Retrieve this module from [PyPi](https://pypi.org) or elsewhere,
then tell Synapse where to look for the handler class by editing the
`saml2_config.user_mapping_provider.module` config option.

`saml2_config.user_mapping_provider.config` allows you to provide custom
configuration options to the module. Check with the module's documentation for
what options it provides (if any). The options listed by default are for the
user mapping provider built in to Synapse. If using a custom module, you should
comment these options out and use those specified by the module instead.

## Building a Custom Mapping Provider

A custom mapping provider must specify the following method:

* `saml_response_to_user_attributes(self, saml_response, failures)`
    - Arguments:
      - `saml_response` - A `saml2.response.AuthnResponse` object to extract user
                          information from.
      - `failures` - An int that represents the amount of times the returned
                     mxid localpart mapping has failed.  This should be used
                     to create a deduplicated mxid localpart which should be
                     returned instead.  For example, if this method returns
                     `john.doe` as the value of `mxid_localpart` in the returned
                     dict, and that is already taken on the homeserver, this
                     method will be called again with the same parameters but
                     with failures=1. The method should then return a different
                     `mxid_localpart` value, such as `john.doe1`.
    - This method must return a dictionary, which will then be used by Synapse
      to build a new user. The following keys are allowed:
       * `mxid_localpart` - Required. The mxid localpart of the new user.
       * `displayname` - The displayname of the new user.

## Synapse's Default Provider

Synapse has a built-in SAML mapping provider if a custom provider isn't
specified in the config. It is located at
[`synapse.handlers.saml_handler.DefaultSamlMappingProvider`](../synapse/handlers/saml_handler.py).
