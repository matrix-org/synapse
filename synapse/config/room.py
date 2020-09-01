# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

from synapse.api.constants import EventTypes, RoomCreationPreset

from ._base import Config, ConfigError

logger = logging.Logger(__name__)


class RoomDefaultEncryptionTypes(object):
    """Possible values for the encryption_enabled_by_default_for_room_type config option"""

    ALL = "all"
    INVITE = "invite"
    OFF = "off"


class RoomConfig(Config):
    section = "room"

    power_level_content_default = {
        "users": {},
        "users_default": 0,
        "events_default": 0,
        "events": {
            EventTypes.Name: 50,
            EventTypes.PowerLevels: 100,
            EventTypes.RoomHistoryVisibility: 100,
            EventTypes.CanonicalAlias: 50,
            EventTypes.RoomAvatar: 50,
            EventTypes.Tombstone: 100,
            EventTypes.ServerACL: 100,
            EventTypes.RoomEncryption: 100,
        },
        "state_default": 50,
        "ban": 50,
        "kick": 50,
        "redact": 50,
        "invite": 50,
    }

    def read_config(self, config, **kwargs):
        # Whether new, locally-created rooms should have encryption enabled
        encryption_for_room_type = config.get(
            "encryption_enabled_by_default_for_room_type",
            RoomDefaultEncryptionTypes.OFF,
        )
        if encryption_for_room_type == RoomDefaultEncryptionTypes.ALL:
            self.encryption_enabled_by_default_for_room_presets = [
                RoomCreationPreset.PRIVATE_CHAT,
                RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
                RoomCreationPreset.PUBLIC_CHAT,
            ]
        elif encryption_for_room_type == RoomDefaultEncryptionTypes.INVITE:
            self.encryption_enabled_by_default_for_room_presets = [
                RoomCreationPreset.PRIVATE_CHAT,
                RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
            ]
        elif (
            encryption_for_room_type == RoomDefaultEncryptionTypes.OFF
            or encryption_for_room_type is False
        ):
            # PyYAML translates "off" into False if it's unquoted, so we also need to
            # check for encryption_for_room_type being False.
            self.encryption_enabled_by_default_for_room_presets = []
        else:
            raise ConfigError(
                "Invalid value for encryption_enabled_by_default_for_room_type"
            )

        # Power level content override for locally-created rooms
        power_level_content_override = config.get("power_level_content_override", {})

        invalid_keys = (
            power_level_content_override.keys()
            - self.power_level_content_default.keys()
        )
        if invalid_keys:
            raise ConfigError(
                "Invalid power level override keys: " + ", ".join(invalid_keys)
            )

        override_events = power_level_content_override.get("events", {})
        invalid_event_keys = (
            override_events.keys() - self.power_level_content_default["events"].keys()
        )
        if invalid_event_keys:
            raise ConfigError(
                "Invalid power level override event keys: "
                + ", ".join(invalid_event_keys)
            )

        self.power_level_content_override = power_level_content_override

    def generate_config_section(self, **kwargs):
        pl_keys = self.power_level_content_default.keys() - {"events", "users"}
        pl_lines = ["          #{}: 50".format(f) for f in pl_keys]
        pl_lines = "\n".join(pl_lines)

        pl_event_keys = self.power_level_content_default["events"].keys()
        pl_event_lines = ["            #{}: 50".format(f) for f in pl_event_keys]
        pl_event_lines = "\n".join(pl_event_lines)

        return f"""\
        ## Rooms ##

        # Controls whether locally-created rooms should be end-to-end encrypted by
        # default.
        #
        # Possible options are "all", "invite", and "off". They are defined as:
        #
        # * "all": any locally-created room
        # * "invite": any room created with the "private_chat" or "trusted_private_chat"
        #             room creation presets
        # * "off": this option will take no effect
        #
        # The default value is "off".
        #
        # Note that this option will only affect rooms created after it is set. It
        # will also not affect rooms created by other servers.
        #
        #encryption_enabled_by_default_for_room_type: invite

        # Don't use this unless you are sure you know what you're doing and have
        # a strong understanding of the matrix protocol. Here's the relevant docs:
        # https://matrix.org/docs/spec/client_server/latest#m-room-power-levels
        #
        # Any values declared in this option will override the named power level
        # event content unconditionally.
        #
        power_level_content_override:
          #
          # Power level event content fields:
{pl_lines}

          # Events list to be sent in the power level event
          #
          events:
{pl_event_lines}
        """
