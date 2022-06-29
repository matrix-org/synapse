# Copyright 2018 New Vector Ltd
# Copyright 2021 Matrix.org Foundation C.I.C.
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

from typing import Any, List

from matrix_common.regex import glob_to_regex

from synapse.types import JsonDict

from ._base import Config, ConfigError


class RoomDirectoryConfig(Config):
    section = "roomdirectory"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.enable_room_list_search = config.get("enable_room_list_search", True)

        alias_creation_rules = config.get("alias_creation_rules")

        if alias_creation_rules is not None:
            self._alias_creation_rules = [
                _RoomDirectoryRule("alias_creation_rules", rule)
                for rule in alias_creation_rules
            ]
        else:
            self._alias_creation_rules = [
                _RoomDirectoryRule("alias_creation_rules", {"action": "allow"})
            ]

        room_list_publication_rules = config.get("room_list_publication_rules")

        if room_list_publication_rules is not None:
            self._room_list_publication_rules = [
                _RoomDirectoryRule("room_list_publication_rules", rule)
                for rule in room_list_publication_rules
            ]
        else:
            self._room_list_publication_rules = [
                _RoomDirectoryRule("room_list_publication_rules", {"action": "allow"})
            ]

    def is_alias_creation_allowed(self, user_id: str, room_id: str, alias: str) -> bool:
        """Checks if the given user is allowed to create the given alias

        Args:
            user_id: The user to check.
            room_id: The room ID for the alias.
            alias: The alias being created.

        Returns:
            True if user is allowed to create the alias
        """
        for rule in self._alias_creation_rules:
            if rule.matches(user_id, room_id, [alias]):
                return rule.action == "allow"

        return False

    def is_publishing_room_allowed(
        self, user_id: str, room_id: str, aliases: List[str]
    ) -> bool:
        """Checks if the given user is allowed to publish the room

        Args:
            user_id: The user ID publishing the room.
            room_id: The room being published.
            aliases: any local aliases associated with the room

        Returns:
            True if user can publish room
        """
        for rule in self._room_list_publication_rules:
            if rule.matches(user_id, room_id, aliases):
                return rule.action == "allow"

        return False


class _RoomDirectoryRule:
    """Helper class to test whether a room directory action is allowed, like
    creating an alias or publishing a room.
    """

    def __init__(self, option_name: str, rule: JsonDict):
        """
        Args:
            option_name: Name of the config option this rule belongs to
            rule: The rule as specified in the config
        """

        action = rule["action"]
        user_id = rule.get("user_id", "*")
        room_id = rule.get("room_id", "*")
        alias = rule.get("alias", "*")

        if action in ("allow", "deny"):
            self.action = action
        else:
            raise ConfigError(
                "%s rules can only have action of 'allow' or 'deny'" % (option_name,)
            )

        self._alias_matches_all = alias == "*"

        try:
            self._user_id_regex = glob_to_regex(user_id)
            self._alias_regex = glob_to_regex(alias)
            self._room_id_regex = glob_to_regex(room_id)
        except Exception as e:
            raise ConfigError("Failed to parse glob into regex") from e

    def matches(self, user_id: str, room_id: str, aliases: List[str]) -> bool:
        """Tests if this rule matches the given user_id, room_id and aliases.

        Args:
            user_id: The user ID to check.
            room_id: The room ID to check.
            aliases: The associated aliases to the room. Will be a single element
                for testing alias creation, and can be empty for testing room
                publishing.

        Returns:
            True if the rule matches.
        """

        # Note: The regexes are anchored at both ends
        if not self._user_id_regex.match(user_id):
            return False

        if not self._room_id_regex.match(room_id):
            return False

        # We only have alias checks left, so we can short circuit if the alias
        # rule matches everything.
        if self._alias_matches_all:
            return True

        # If we are not given any aliases then this rule only matches if the
        # alias glob matches all aliases, which we checked above.
        if not aliases:
            return False

        # Otherwise, we just need one alias to match
        for alias in aliases:
            if self._alias_regex.match(alias):
                return True

        return False
