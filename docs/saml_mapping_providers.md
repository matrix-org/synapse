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
where SAML mapping providers come in.

## Enabling Providers

External mapping providers are provided to Synapse in the form of a external
Python module. Retrieve this module from [PyPi](https://pypi.org) or elsewhere,
then tell Synapse where to look for the handler class by changing the
`saml2_config.user_mapping_provider` config option.

`saml2_config.user_mapping_provider_config` allows you to provide custom
configuration options to the module. Check with the module's documentation for
what options it provides (if any).

## Building a Custom Mapping Provider

A custom mapping provider must specify the following methods:

* `saml_response_to_user_attributes`
    - Receives the `type` object from a SAML response. This method must return a
      dictionary, which will then be used by Synapse to build a new user. The
      following keys are allowed:
       * displayname (required)
       * user_id_localpart (required)
       * avatar_url
* `parse_config(config: dict)`
    - Receives the parsed content of the `saml2_config.user_mapping_provider`
      homeserver config option. Runs on homeserver startup. Providers should
      extract any option values they need here.

## Synapse's Default Provider

Synapse has a built-in SAML mapping provider if a custom provider isn't
specified in the config. It is located at
[`synapse.handlers.saml_handler.DefaultSamlMappingProvider`](../synapse/handlers/saml_handler.py).
