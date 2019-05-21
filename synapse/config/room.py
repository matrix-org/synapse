# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS

from ._base import Config, ConfigError


class RoomConfig(Config):
    def read_config(self, config):
        self.default_room_version = config.get(
            "default_room_version", "1",
        )

        if self.default_room_version not in KNOWN_ROOM_VERSIONS:
            raise ConfigError(
                "Unknown default_room_version: %s, known room versions: %s" %
                (self.default_room_version, KNOWN_ROOM_VERSIONS.keys)
            )

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # The default room version for newly created rooms.
        #
        # Known room versions are listed here:
        # https://matrix.org/docs/spec/#complete-list-of-room-versions
        #
        # For example, for room version 1, default_room_version should be set
        # to "1".
        default_room_version: "1"
        """
