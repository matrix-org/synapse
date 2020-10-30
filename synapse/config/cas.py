# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from ._base import Config


class CasConfig(Config):
    """Cas Configuration

    cas_server_url: URL of CAS server
    """

    section = "cas"

    def read_config(self, config, **kwargs):
        cas_config = config.get("cas_config", None)
        self.cas_enabled = cas_config and cas_config.get("enabled", True)

        if self.cas_enabled:
            self.cas_server_url = cas_config["server_url"]
            self.cas_service_url = cas_config["service_url"]
            self.cas_displayname_attribute = cas_config.get("displayname_attribute")
            self.cas_required_attributes = cas_config.get("required_attributes") or {}
        else:
            self.cas_server_url = None
            self.cas_service_url = None
            self.cas_displayname_attribute = None
            self.cas_required_attributes = {}

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable Central Authentication Service (CAS) for registration and login.
        #
        cas_config:
          # Uncomment the following to enable authorization against a CAS server.
          # Defaults to false.
          #
          #enabled: true

          # The URL of the CAS authorization endpoint.
          #
          #server_url: "https://cas-server.com"

          # The public URL of the homeserver.
          #
          #service_url: "https://homeserver.domain.com:8448"

          # The attribute of the CAS response to use as the display name.
          #
          # If unset, no displayname will be set.
          #
          #displayname_attribute: name

          # It is possible to configure Synapse to only allow logins if CAS attributes
          # match particular values. All of the keys in the mapping below must exist
          # and the values must match the given value. Alternately if the given value
          # is None then any value is allowed (the attribute just must exist).
          # All of the listed attributes must match for the login to be permitted.
          #
          #required_attributes:
          #  userGroup: "staff"
          #  department: None
        """
