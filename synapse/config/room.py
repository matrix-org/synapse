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
from typing import Any

from synapse.api.constants import RoomCreationPreset
from synapse.types import JsonDict

from ._base import Config, ConfigError

logger = logging.Logger(__name__)


class RoomDefaultEncryptionTypes:
    """Possible values for the encryption_enabled_by_default_for_room_type config option"""

    ALL = "all"
    INVITE = "invite"
    OFF = "off"


class RoomConfig(Config):
    section = "room"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
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

        self.default_power_level_content_override = config.get(
            "default_power_level_content_override",
            None,
        )
        if self.default_power_level_content_override is not None:
            for preset in self.default_power_level_content_override:
                if preset not in vars(RoomCreationPreset).values():
                    raise ConfigError(
                        "Unrecognised room preset %s in default_power_level_content_override"
                        % preset
                    )
                # We validate the actual overrides when we try to apply them.

    def generate_config_section(self, **kwargs: Any) -> str:
        return """\
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

        # Override the default power levels for rooms created on this server, per
        # room creation preset.
        #
        # The appropriate dictionary for the room preset will be applied on top
        # of the existing power levels content.
        #
        # Useful if you know that your users need special permissions in rooms
        # that they create (e.g. to send particular types of state events without
        # needing an elevated power level).  This takes the same shape as the
        # `power_level_content_override` parameter in the /createRoom API, but
        # is applied before that parameter.
        #
        # Valid keys are some or all of `private_chat`, `trusted_private_chat`
        # and `public_chat`. Inside each of those should be any of the
        # properties allowed in `power_level_content_override` in the
        # /createRoom API. If any property is missing, its default value will
        # continue to be used. If any property is present, it will overwrite
        # the existing default completely (so if the `events` property exists,
        # the default event power levels will be ignored).
        #
        #default_power_level_content_override:
        #    private_chat:
        #        "events":
        #            "com.example.myeventtype" : 0
        #            "m.room.avatar": 50
        #            "m.room.canonical_alias": 50
        #            "m.room.encryption": 100
        #            "m.room.history_visibility": 100
        #            "m.room.name": 50
        #            "m.room.power_levels": 100
        #            "m.room.server_acl": 100
        #            "m.room.tombstone": 100
        #        "events_default": 1
        """
