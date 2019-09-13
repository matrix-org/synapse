# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
import re

from synapse.python_dependencies import DependencyException, check_requirements
from synapse.types import (
    map_username_to_mxid_localpart,
    mxid_localpart_allowed_characters,
)

from ._base import Config, ConfigError


class SAML2Config(Config):
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
            raise ConfigError(e.message)

        self.saml2_enabled = True

        self.saml2_mxid_source_attribute = saml2_config.get(
            "mxid_source_attribute", "uid"
        )

        self.saml2_grandfathered_mxid_source_attribute = saml2_config.get(
            "grandfathered_mxid_source_attribute", "uid"
        )

        import saml2.config

        self.saml2_sp_config = saml2.config.SPConfig()
        self.saml2_sp_config.load(self._default_saml_config_dict())
        self.saml2_sp_config.load(saml2_config.get("sp_config", {}))

        config_path = saml2_config.get("config_path", None)
        if config_path is not None:
            self.saml2_sp_config.load_file(config_path)

        # session lifetime: in milliseconds
        self.saml2_session_lifetime = self.parse_duration(
            saml2_config.get("saml_session_lifetime", "5m")
        )

        mapping = saml2_config.get("mxid_mapping", "hexencode")
        try:
            self.saml2_mxid_mapper = MXID_MAPPER_MAP[mapping]
        except KeyError:
            raise ConfigError("%s is not a known mxid_mapping" % (mapping,))

    def _default_saml_config_dict(self):
        import saml2

        public_baseurl = self.public_baseurl
        if public_baseurl is None:
            raise ConfigError("saml2_config requires a public_baseurl to be set")

        required_attributes = {"uid", self.saml2_mxid_source_attribute}

        optional_attributes = {"displayName"}
        if self.saml2_grandfathered_mxid_source_attribute:
            optional_attributes.add(self.saml2_grandfathered_mxid_source_attribute)
        optional_attributes -= required_attributes

        metadata_url = public_baseurl + "_matrix/saml2/metadata.xml"
        response_url = public_baseurl + "_matrix/saml2/authn_response"
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

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # Enable SAML2 for registration and login. Uses pysaml2.
        #
        # At least one of `sp_config` or `config_path` must be set in this section to
        # enable SAML login.
        #
        # (You will probably also want to set the following options to `false` to
        # disable the regular login/registration flows:
        #   * enable_registration
        #   * password_config.enabled
        #
        # Once SAML support is enabled, a metadata file will be exposed at
        # https://<server>:<port>/_matrix/saml2/metadata.xml, which you may be able to
        # use to configure your SAML IdP with. Alternatively, you can manually configure
        # the IdP to use an ACS location of
        # https://<server>:<port>/_matrix/saml2/authn_response.
        #
        saml2_config:
          # `sp_config` is the configuration for the pysaml2 Service Provider.
          # See pysaml2 docs for format of config.
          #
          # Default values will be used for the 'entityid' and 'service' settings,
          # so it is not normally necessary to specify them unless you need to
          # override them.
          #
          #sp_config:
          #  # point this to the IdP's metadata. You can use either a local file or
          #  # (preferably) a URL.
          #  metadata:
          #    #local: ["saml2/idp.xml"]
          #    remote:
          #      - url: https://our_idp/metadata.xml
          #
          #    # By default, the user has to go to our login page first. If you'd like
          #    # to allow IdP-initiated login, set 'allow_unsolicited: True' in a
          #    # 'service.sp' section:
          #    #
          #    #service:
          #    #  sp:
          #    #    allow_unsolicited: true
          #
          #    # The examples below are just used to generate our metadata xml, and you
          #    # may well not need them, depending on your setup. Alternatively you
          #    # may need a whole lot more detail - see the pysaml2 docs!
          #
          #    description: ["My awesome SP", "en"]
          #    name: ["Test SP", "en"]
          #
          #    organization:
          #      name: Example com
          #      display_name:
          #        - ["Example co", "en"]
          #      url: "http://example.com"
          #
          #    contact_person:
          #      - given_name: Bob
          #        sur_name: "the Sysadmin"
          #        email_address": ["admin@example.com"]
          #        contact_type": technical

          # Instead of putting the config inline as above, you can specify a
          # separate pysaml2 configuration file:
          #
          #config_path: "%(config_dir_path)s/sp_conf.py"

          # the lifetime of a SAML session. This defines how long a user has to
          # complete the authentication process, if allow_unsolicited is unset.
          # The default is 5 minutes.
          #
          #saml_session_lifetime: 5m

          # The SAML attribute (after mapping via the attribute maps) to use to derive
          # the Matrix ID from. 'uid' by default.
          #
          #mxid_source_attribute: displayName

          # The mapping system to use for mapping the saml attribute onto a matrix ID.
          # Options include:
          #  * 'hexencode' (which maps unpermitted characters to '=xx')
          #  * 'dotreplace' (which replaces unpermitted characters with '.').
          # The default is 'hexencode'.
          #
          #mxid_mapping: dotreplace

          # In previous versions of synapse, the mapping from SAML attribute to MXID was
          # always calculated dynamically rather than stored in a table. For backwards-
          # compatibility, we will look for user_ids matching such a pattern before
          # creating a new account.
          #
          # This setting controls the SAML attribute which will be used for this
          # backwards-compatibility lookup. Typically it should be 'uid', but if the
          # attribute maps are changed, it may be necessary to change it.
          #
          # The default is 'uid'.
          #
          #grandfathered_mxid_source_attribute: upn
        """ % {
            "config_dir_path": config_dir_path
        }


DOT_REPLACE_PATTERN = re.compile(
    ("[^%s]" % (re.escape("".join(mxid_localpart_allowed_characters)),))
)


def dot_replace_for_mxid(username: str) -> str:
    username = username.lower()
    username = DOT_REPLACE_PATTERN.sub(".", username)

    # regular mxids aren't allowed to start with an underscore either
    username = re.sub("^_", "", username)
    return username


MXID_MAPPER_MAP = {
    "hexencode": map_username_to_mxid_localpart,
    "dotreplace": dot_replace_for_mxid,
}
