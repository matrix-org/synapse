# Copyright 2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import logging
from typing import Any, List

from synapse.config.sso import SsoAttributeRequirement
from synapse.python_dependencies import DependencyException, check_requirements
from synapse.util import dict_merge
from synapse.util.module_loader import load_module, load_python_module

from ._base import Config, ConfigError
from ._util import validate_config

logger = logging.getLogger(__name__)

DEFAULT_USER_MAPPING_PROVIDER = "synapse.handlers.saml.DefaultSamlMappingProvider"
# The module that DefaultSamlMappingProvider is in was renamed, we want to
# transparently handle both the same.
LEGACY_USER_MAPPING_PROVIDER = (
    "synapse.handlers.saml_handler.DefaultSamlMappingProvider"
)


class SAML2Config(Config):
    section = "saml2"

    def read_config(self, config, **kwargs):
        self.saml2_enabled = False

        saml2_config = config.get("saml2_config")

        if not saml2_config or not saml2_config.get("enabled", True):
            return

        if not saml2_config.get("sp_config") and not saml2_config.get("config_path"):
            return

        try:
            check_requirements("saml2")
        except DependencyException as e:
            raise ConfigError(
                e.message  # noqa: B306, DependencyException.message is a property
            )

        self.saml2_enabled = True

        attribute_requirements = saml2_config.get("attribute_requirements") or []
        self.attribute_requirements = _parse_attribute_requirements_def(
            attribute_requirements
        )

        self.saml2_grandfathered_mxid_source_attribute = saml2_config.get(
            "grandfathered_mxid_source_attribute", "uid"
        )

        self.saml2_idp_entityid = saml2_config.get("idp_entityid", None)

        # user_mapping_provider may be None if the key is present but has no value
        ump_dict = saml2_config.get("user_mapping_provider") or {}

        # Use the default user mapping provider if not set
        # NOTE this is the legacy way of using custom modules
        # New style-modules should be placed in the 'modules:' config section
        ump_dict.setdefault("module", DEFAULT_USER_MAPPING_PROVIDER)
        if ump_dict.get("module") == LEGACY_USER_MAPPING_PROVIDER:
            ump_dict["module"] = DEFAULT_USER_MAPPING_PROVIDER

        # Ensure a config is present
        # This is the config for the default mapping provider, or the legacy
        # way of configuring a custom module
        ump_dict["config"] = ump_dict.get("config") or {}

        if ump_dict["module"] == DEFAULT_USER_MAPPING_PROVIDER:
            # Load deprecated options for use by the default module
            old_mxid_source_attribute = saml2_config.get("mxid_source_attribute")
            if old_mxid_source_attribute:
                logger.warning(
                    "The config option saml2_config.mxid_source_attribute is deprecated. "
                    "Please use saml2_config.user_mapping_provider.config"
                    ".mxid_source_attribute instead."
                )
                ump_dict["config"]["mxid_source_attribute"] = old_mxid_source_attribute

            old_mxid_mapping = saml2_config.get("mxid_mapping")
            if old_mxid_mapping:
                logger.warning(
                    "The config option saml2_config.mxid_mapping is deprecated. Please "
                    "use saml2_config.user_mapping_provider.config.mxid_mapping instead."
                )
                ump_dict["config"]["mxid_mapping"] = old_mxid_mapping

        # Retrieve an instance of the module's class
        # Pass the config dictionary to the module for processing
        (
            self.saml2_user_mapping_provider_class,
            self.saml2_user_mapping_provider_config,
        ) = load_module(ump_dict, ("saml2_config", "user_mapping_provider"))

        # This is only the *base* config since a custom user mapping provider can change
        # the values of 'service.sp.required_attributes' and 'service.sp.optional_attributes'
        self.base_sp_config = self._default_sp_config_dict()
        dict_merge(
            merge_dict=saml2_config.get("sp_config", {}), into_dict=self.base_sp_config
        )

        sp_config_path = saml2_config.get("config_path", None)
        if sp_config_path is not None:
            mod = load_python_module(sp_config_path)
            sp_config_from_file = getattr(mod, "CONFIG", None)
            if sp_config_from_file is None:
                raise ConfigError(
                    "Config path specified by saml2_config.config_path does not "
                    "have a CONFIG property."
                )
            dict_merge(merge_dict=sp_config_from_file, into_dict=self.base_sp_config)

        # session lifetime: in milliseconds
        self.saml2_session_lifetime = self.parse_duration(
            saml2_config.get("saml_session_lifetime", "15m")
        )

    def _default_sp_config_dict(self):
        """Generate a configuration dictionary with required and optional attributes that
        will be needed to process new user registration

        Args:
            required_attributes: SAML auth response attributes that are
                necessary to function
            optional_attributes: SAML auth response attributes that can be used to add
                additional information to Synapse user accounts, but are not required

        Returns:
            dict: A SAML configuration dictionary
        """
        import saml2

        public_baseurl = self.public_baseurl
        if public_baseurl is None:
            raise ConfigError("saml2_config requires a public_baseurl to be set")

        metadata_url = public_baseurl + "_synapse/client/saml2/metadata.xml"
        response_url = public_baseurl + "_synapse/client/saml2/authn_response"
        return {
            "entityid": metadata_url,
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            (response_url, saml2.BINDING_HTTP_POST)
                        ]
                    },
                    # "name_id_format": saml2.saml.NAMEID_FORMAT_PERSISTENT,
                }
            },
        }

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        ## Single sign-on integration ##

        # The following settings can be used to make Synapse use a single sign-on
        # provider for authentication, instead of its internal password database.
        #
        # You will probably also want to set the following options to `false` to
        # disable the regular login/registration flows:
        #   * enable_registration
        #   * password_config.enabled
        #
        # You will also want to investigate the settings under the "sso" configuration
        # section below.

        # Enable SAML2 for registration and login. Uses pysaml2.
        #
        # At least one of `sp_config` or `config_path` must be set in this section to
        # enable SAML login.
        #
        # Once SAML support is enabled, a metadata file will be exposed at
        # https://<server>:<port>/_synapse/client/saml2/metadata.xml, which you may be able to
        # use to configure your SAML IdP with. Alternatively, you can manually configure
        # the IdP to use an ACS location of
        # https://<server>:<port>/_synapse/client/saml2/authn_response.
        #
        saml2_config:
          # `sp_config` is the configuration for the pysaml2 Service Provider.
          # See pysaml2 docs for format of config.
          #
          # Default values will be used for the 'entityid' and 'service' settings,
          # so it is not normally necessary to specify them unless you need to
          # override them. Note that setting 'service.sp.required_attributes' or
          # 'service.sp.optional_attributes' here will override anything configured
          # by a module that registers saml2 user mapping provider callbacks
          #
          sp_config:
            # Point this to the IdP's metadata. You must provide either a local
            # file via the `local` attribute or (preferably) a URL via the
            # `remote` attribute.
            #
            #metadata:
            #  local: ["saml2/idp.xml"]
            #  remote:
            #    - url: https://our_idp/metadata.xml

            # Allowed clock difference in seconds between the homeserver and IdP.
            #
            # Uncomment the below to increase the accepted time difference from 0 to 3 seconds.
            #
            #accepted_time_diff: 3

            # By default, the user has to go to our login page first. If you'd like
            # to allow IdP-initiated login, set 'allow_unsolicited: true' in a
            # 'service.sp' section:
            #
            #service:
            #  sp:
            #    allow_unsolicited: true

            # The examples below are just used to generate our metadata xml, and you
            # may well not need them, depending on your setup. Alternatively you
            # may need a whole lot more detail - see the pysaml2 docs!

            #description: ["My awesome SP", "en"]
            #name: ["Test SP", "en"]

            #ui_info:
            #  display_name:
            #    - lang: en
            #      text: "Display Name is the descriptive name of your service."
            #  description:
            #    - lang: en
            #      text: "Description should be a short paragraph explaining the purpose of the service."
            #  information_url:
            #    - lang: en
            #      text: "https://example.com/terms-of-service"
            #  privacy_statement_url:
            #    - lang: en
            #      text: "https://example.com/privacy-policy"
            #  keywords:
            #    - lang: en
            #      text: ["Matrix", "Element"]
            #  logo:
            #    - lang: en
            #      text: "https://example.com/logo.svg"
            #      width: "200"
            #      height: "80"

            #organization:
            #  name: Example com
            #  display_name:
            #    - ["Example co", "en"]
            #  url: "http://example.com"

            #contact_person:
            #  - given_name: Bob
            #    sur_name: "the Sysadmin"
            #    email_address": ["admin@example.com"]
            #    contact_type": technical

          # Instead of putting the config inline as above, you can specify a
          # separate pysaml2 configuration file:
          #
          #config_path: "%(config_dir_path)s/sp_conf.py"

          # The lifetime of a SAML session. This defines how long a user has to
          # complete the authentication process, if allow_unsolicited is unset.
          # The default is 15 minutes.
          #
          #saml_session_lifetime: 5m

          # Setting for the default mapping provider which maps attributes returned
          # from a saml provider onto a matrix user. Custom solutions can be used by
          # adding a module that provides these features to the 'modules' config
          # section, in which case the following section will be ignored.
          #
          user_mapping_provider:
            # Custom configuration values for the module. Below options are
            # intended for the built-in provider.
            #
            config:
              # The SAML attribute (after mapping via the attribute maps) to use
              # to derive the Matrix ID from. 'uid' by default.
              #
              # Note: This used to be configured by the
              # saml2_config.mxid_source_attribute option. If that is still
              # defined, its value will be used instead.
              #
              #mxid_source_attribute: displayName

              # The mapping system to use for mapping the saml attribute onto a
              # matrix ID.
              #
              # Options include:
              #  * 'hexencode' (which maps unpermitted characters to '=xx')
              #  * 'dotreplace' (which replaces unpermitted characters with
              #     '.').
              # The default is 'hexencode'.
              #
              # Note: This used to be configured by the
              # saml2_config.mxid_mapping option. If that is still defined, its
              # value will be used instead.
              #
              #mxid_mapping: dotreplace

          # In previous versions of synapse, the mapping from SAML attribute to
          # MXID was always calculated dynamically rather than stored in a
          # table. For backwards- compatibility, we will look for user_ids
          # matching such a pattern before creating a new account.
          #
          # This setting controls the SAML attribute which will be used for this
          # backwards-compatibility lookup. Typically it should be 'uid', but if
          # the attribute maps are changed, it may be necessary to change it.
          #
          # The default is 'uid'.
          #
          #grandfathered_mxid_source_attribute: upn

          # It is possible to configure Synapse to only allow logins if SAML attributes
          # match particular values. The requirements can be listed under
          # `attribute_requirements` as shown below. All of the listed attributes must
          # match for the login to be permitted.
          #
          #attribute_requirements:
          #  - attribute: userGroup
          #    value: "staff"
          #  - attribute: department
          #    value: "sales"

          # If the metadata XML contains multiple IdP entities then the `idp_entityid`
          # option must be set to the entity to redirect users to.
          #
          # Most deployments only have a single IdP entity and so should omit this
          # option.
          #
          #idp_entityid: 'https://our_idp/entityid'
        """ % {
            "config_dir_path": config_dir_path
        }


ATTRIBUTE_REQUIREMENTS_SCHEMA = {
    "type": "array",
    "items": SsoAttributeRequirement.JSON_SCHEMA,
}


def _parse_attribute_requirements_def(
    attribute_requirements: Any,
) -> List[SsoAttributeRequirement]:
    validate_config(
        ATTRIBUTE_REQUIREMENTS_SCHEMA,
        attribute_requirements,
        config_path=("saml2_config", "attribute_requirements"),
    )
    return [SsoAttributeRequirement(**x) for x in attribute_requirements]
