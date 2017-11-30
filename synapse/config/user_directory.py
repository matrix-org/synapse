# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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


class UserDirectoryConfig(Config):
    """User Directory Configuration
    Configuration for the behaviour of the /user_directory API
    """

    def read_config(self, config):
        self.user_directory_include_pattern = None
        user_directory_config = config.get("user_directory", None)
        if user_directory_config:
            self.user_directory_include_pattern = (
                user_directory_config.get("include_pattern", None)
            )

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # User Directory configuration
        # 'include_pattern' defines an optional SQL LIKE pattern when querying the
        # user directory in addition to publicly visible users. Defaults to None.
        #
        #user_directory:
        #   include_pattern: "%%:%s"
        """ % (server_name)
