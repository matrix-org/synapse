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


class GroupsConfig(Config):
    def read_config(self, config):
        self.enable_group_creation = config.get("enable_group_creation", False)
        self.group_creation_prefix = config.get("group_creation_prefix", "")

    def default_config(self, **kwargs):
        return """\
        # Uncomment to allow non-server-admin users to create groups on this server
        #
        #enable_group_creation: true

        # If enabled, non server admins can only create groups with local parts
        # starting with this prefix
        #
        #group_creation_prefix: "unofficial/"
        """
