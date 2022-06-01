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
