# Copyright 2015-2021 The Matrix.org Foundation C.I.C.
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
from typing import Iterable

from synapse.api.constants import EventTypes
from synapse.config._base import Config, ConfigError
from synapse.config._util import validate_config
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class ApiConfig(Config):
    section = "api"

    def read_config(self, config: JsonDict, **kwargs):
        validate_config(_MAIN_SCHEMA, config, ())
        self.room_prejoin_state = list(self._get_prejoin_state_types(config))

    def generate_config_section(cls, **kwargs) -> str:
        formatted_default_state_types = "\n".join(
            "           # - %s" % (t,) for t in _DEFAULT_PREJOIN_STATE_TYPES
        )

        return """\
        ## API Configuration ##

        # Controls for the state that is shared with users who receive an invite
        # to a room
        #
        room_prejoin_state:
           # By default, the following state event types are shared with users who
           # receive invites to the room:
           #
%(formatted_default_state_types)s
           #
           # Uncomment the following to disable these defaults (so that only the event
           # types listed in 'additional_event_types' are shared). Defaults to 'false'.
           #
           #disable_default_event_types: true

           # Additional state event types to share with users when they are invited
           # to a room.
           #
           # By default, this list is empty (so only the default event types are shared).
           #
           #additional_event_types:
           #  - org.example.custom.event.type
        """ % {
            "formatted_default_state_types": formatted_default_state_types
        }

    def _get_prejoin_state_types(self, config: JsonDict) -> Iterable[str]:
        """Get the event types to include in the prejoin state

        Parses the config and returns an iterable of the event types to be included.
        """
        room_prejoin_state_config = config.get("room_prejoin_state") or {}

        # backwards-compatibility support for room_invite_state_types
        if "room_invite_state_types" in config:
            # if both "room_invite_state_types" and "room_prejoin_state" are set, then
            # we don't really know what to do.
            if room_prejoin_state_config:
                raise ConfigError(
                    "Can't specify both 'room_invite_state_types' and 'room_prejoin_state' "
                    "in config"
                )

            logger.warning(_ROOM_INVITE_STATE_TYPES_WARNING)

            yield from config["room_invite_state_types"]
            return

        if not room_prejoin_state_config.get("disable_default_event_types"):
            yield from _DEFAULT_PREJOIN_STATE_TYPES

        yield from room_prejoin_state_config.get("additional_event_types", [])


_ROOM_INVITE_STATE_TYPES_WARNING = """\
WARNING: The 'room_invite_state_types' configuration setting is now deprecated,
and replaced with 'room_prejoin_state'. New features may not work correctly
unless 'room_invite_state_types' is removed. See the sample configuration file for
details of 'room_prejoin_state'.
--------------------------------------------------------------------------------
"""

_DEFAULT_PREJOIN_STATE_TYPES = [
    EventTypes.JoinRules,
    EventTypes.CanonicalAlias,
    EventTypes.RoomAvatar,
    EventTypes.RoomEncryption,
    EventTypes.Name,
    # Per MSC1772.
    EventTypes.Create,
]


# room_prejoin_state can either be None (as it is in the default config), or
# an object containing other config settings
_ROOM_PREJOIN_STATE_CONFIG_SCHEMA = {
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "disable_default_event_types": {"type": "boolean"},
                "additional_event_types": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
        {"type": "null"},
    ]
}

# the legacy room_invite_state_types setting
_ROOM_INVITE_STATE_TYPES_SCHEMA = {"type": "array", "items": {"type": "string"}}

_MAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "room_prejoin_state": _ROOM_PREJOIN_STATE_CONFIG_SCHEMA,
        "room_invite_state_types": _ROOM_INVITE_STATE_TYPES_SCHEMA,
    },
}
