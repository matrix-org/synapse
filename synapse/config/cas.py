# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

    def read_config(self, config):
        cas_config = config.get("cas_config", None)
        if cas_config:
            self.cas_enabled = True
            self.cas_server_url = cas_config["server_url"]

            if "required_attribute" in cas_config:
                self.cas_required_attribute = cas_config["required_attribute"]
            else:
                self.cas_required_attribute = None

            if "required_attribute_value" in cas_config:
                self.cas_required_attribute_value = cas_config["required_attribute_value"]
            else:
                self.cas_required_attribute_value = None

        else:
            self.cas_enabled = False
            self.cas_server_url = None
            self.cas_required_attribute = None
            self.cas_required_attribute_value = None

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable CAS for registration and login.
        #cas_config:
        #   server_url: "https://cas-server.com"
        #   #required_attribute: something
        #   #required_attribute_value: true
        """
