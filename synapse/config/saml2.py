# Copyright 2018 New Vector Ltd
# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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
from typing import Any, List, Set

from synapse.config.sso import SsoAttributeRequirement
from synapse.types import JsonDict
from synapse.util.check_dependencies import check_requirements
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


def _dict_merge(merge_dict: dict, into_dict: dict) -> None:
    """Do a deep merge of two dicts

    Recursively merges `merge_dict` into `into_dict`:
      * For keys where both `merge_dict` and `into_dict` have a dict value, the values
        are recursively merged
      * For all other keys, the values in `into_dict` (if any) are overwritten with
        the value from `merge_dict`.

    Args:
        merge_dict: dict to merge
        into_dict: target dict to be modified
    """
    for k, v in merge_dict.items():
        if k not in into_dict:
            into_dict[k] = v
            continue

        current_val = into_dict[k]

        if isinstance(v, dict) and isinstance(current_val, dict):
            _dict_merge(v, current_val)
            continue

        # otherwise we just overwrite
        into_dict[k] = v


class SAML2Config(Config):
    section = "saml2"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.saml2_enabled = False

        saml2_config = config.get("saml2_config")

        if not saml2_config or not saml2_config.get("enabled", True):
            return

        if not saml2_config.get("sp_config") and not saml2_config.get("config_path"):
            return

        check_requirements("saml2")

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
        ump_dict.setdefault("module", DEFAULT_USER_MAPPING_PROVIDER)
        if ump_dict.get("module") == LEGACY_USER_MAPPING_PROVIDER:
            ump_dict["module"] = DEFAULT_USER_MAPPING_PROVIDER

        # Ensure a config is present
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

        # Ensure loaded user mapping module has defined all necessary methods
        # Note parse_config() is already checked during the call to load_module
        required_methods = [
            "get_saml_attributes",
            "saml_response_to_user_attributes",
            "get_remote_user_id",
        ]
        missing_methods = [
            method
            for method in required_methods
            if not hasattr(self.saml2_user_mapping_provider_class, method)
        ]
        if missing_methods:
            raise ConfigError(
                "Class specified by saml2_config."
                "user_mapping_provider.module is missing required "
                "methods: %s" % (", ".join(missing_methods),)
            )

        # Get the desired saml auth response attributes from the module
        saml2_config_dict = self._default_saml_config_dict(
            *self.saml2_user_mapping_provider_class.get_saml_attributes(
                self.saml2_user_mapping_provider_config
            )
        )
        _dict_merge(
            merge_dict=saml2_config.get("sp_config", {}), into_dict=saml2_config_dict
        )

        config_path = saml2_config.get("config_path", None)
        if config_path is not None:
            mod = load_python_module(config_path)
            config_dict_from_file = getattr(mod, "CONFIG", None)
            if config_dict_from_file is None:
                raise ConfigError(
                    "Config path specified by saml2_config.config_path does not "
                    "have a CONFIG property."
                )
            _dict_merge(merge_dict=config_dict_from_file, into_dict=saml2_config_dict)

        import saml2.config

        self.saml2_sp_config = saml2.config.SPConfig()
        self.saml2_sp_config.load(saml2_config_dict)

        # session lifetime: in milliseconds
        self.saml2_session_lifetime = self.parse_duration(
            saml2_config.get("saml_session_lifetime", "15m")
        )

    def _default_saml_config_dict(
        self, required_attributes: Set[str], optional_attributes: Set[str]
    ) -> JsonDict:
        """Generate a configuration dictionary with required and optional attributes that
        will be needed to process new user registration

        Args:
            required_attributes: SAML auth response attributes that are
                necessary to function
            optional_attributes: SAML auth response attributes that can be used to add
                additional information to Synapse user accounts, but are not required

        Returns:
            A SAML configuration dictionary
        """
        import saml2

        if self.saml2_grandfathered_mxid_source_attribute:
            optional_attributes.add(self.saml2_grandfathered_mxid_source_attribute)
        optional_attributes -= required_attributes

        public_baseurl = self.root.server.public_baseurl
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
                    "required_attributes": list(required_attributes),
                    "optional_attributes": list(optional_attributes),
                    # "name_id_format": saml2.saml.NAMEID_FORMAT_PERSISTENT,
                }
            },
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
