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

from synapse.util import glob_to_regex

from ._base import Config, ConfigError


class RoomDirectoryConfig(Config):
    def read_config(self, config):
        alias_creation_rules = config["alias_creation_rules"]

        self._alias_creation_rules = [
            _AliasRule(rule)
            for rule in alias_creation_rules
        ]

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # The `alias_creation` option controls who's allowed to create aliases
        # on this server.
        #
        # The format of this option is a list of rules that contain globs that
        # match against user_id and the new alias (fully qualified with server
        # name). The action in the first rule that matches is taken, which can
        # currently either be "allowed" or "denied".
        #
        # If no rules match the request is denied.
        alias_creation_rules:
            - user_id: "*"
              alias: "*"
              action: allowed
        """

    def is_alias_creation_allowed(self, user_id, alias):
        """Checks if the given user is allowed to create the given alias

        Args:
            user_id (str)
            alias (str)

        Returns:
            boolean: True if user is allowed to crate the alias
        """
        for rule in self._alias_creation_rules:
            if rule.matches(user_id, alias):
                return rule.action == "allowed"

        return False


class _AliasRule(object):
    def __init__(self, rule):
        action = rule["action"]
        user_id = rule["user_id"]
        alias = rule["alias"]

        if action in ("allowed", "denied"):
            self.action = action
        else:
            raise ConfigError(
                "alias_creation_rules rules can only have action of 'allowed'"
                " or 'denied'"
            )

        try:
            self._user_id_regex = glob_to_regex(user_id)
            self._alias_regex = glob_to_regex(alias)
        except Exception as e:
            raise ConfigError("Failed to parse glob into regex: %s", e)

    def matches(self, user_id, alias):
        """Tests if this rule matches the given user_id and alias.

        Args:
            user_id (str)
            alias (str)

        Returns:
            boolean
        """

        if not self._user_id_regex.search(user_id):
            return False

        if not self._alias_regex.search(alias):
            return False

        return True
