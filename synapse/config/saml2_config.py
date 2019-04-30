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

from ._base import Config, ConfigError


class SAML2Config(Config):
    def read_config(self, config):
        self.saml2_enabled = False

        saml2_config = config.get("saml2_config")

        if not saml2_config or not saml2_config.get("enabled", True):
            return

        self.saml2_enabled = True

        import saml2.config
        self.saml2_sp_config = saml2.config.SPConfig()
        self.saml2_sp_config.load(self._default_saml_config_dict())
        self.saml2_sp_config.load(saml2_config.get("sp_config", {}))

        config_path = saml2_config.get("config_path", None)
        if config_path is not None:
            self.saml2_sp_config.load_file(config_path)

    def _default_saml_config_dict(self):
        import saml2

        public_baseurl = self.public_baseurl
        if public_baseurl is None:
            raise ConfigError(
                "saml2_config requires a public_baseurl to be set"
            )

        metadata_url = public_baseurl + "_matrix/saml2/metadata.xml"
        response_url = public_baseurl + "_matrix/saml2/authn_response"
        return {
            "entityid": metadata_url,

            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            (response_url, saml2.BINDING_HTTP_POST),
                        ],
                    },
                    "required_attributes": ["uid"],
                    "optional_attributes": ["mail", "surname", "givenname"],
                },
            }
        }

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """\
        # Enable SAML2 for registration and login. Uses pysaml2.
        #
        # `sp_config` is the configuration for the pysaml2 Service Provider.
        # See pysaml2 docs for format of config.
        #
        # Default values will be used for the 'entityid' and 'service' settings,
        # so it is not normally necessary to specify them unless you need to
        # override them.
        #
        #saml2_config:
        #  sp_config:
        #    # point this to the IdP's metadata. You can use either a local file or
        #    # (preferably) a URL.
        #    metadata:
        #      #local: ["saml2/idp.xml"]
        #      remote:
        #        - url: https://our_idp/metadata.xml
        #
        #    # The rest of sp_config is just used to generate our metadata xml, and you
        #    # may well not need it, depending on your setup. Alternatively you
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
        #
        #  # Instead of putting the config inline as above, you can specify a
        #  # separate pysaml2 configuration file:
        #  #
        #  config_path: "%(config_dir_path)s/sp_conf.py"
        """ % {"config_dir_path": config_dir_path}
