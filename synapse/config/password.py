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


class PasswordConfig(Config):
    """Password login configuration
    """

    def read_config(self, config):
        password_config = config.get("password_config", {})
        self.password_enabled = password_config.get("enabled", True)
        self.password_pepper = password_config.get("pepper", "")

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable password for login.
        password_config:
           enabled: true
           # Uncomment and change to a secret random string for extra security.
           # DO NOT CHANGE THIS AFTER INITIAL SETUP!
           #pepper: ""
        """
