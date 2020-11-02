# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.constants import EventTypes

from ._base import Config


class ApiConfig(Config):
    section = "api"

    def read_config(self, config, **kwargs):
        default_room_state_types = [
            EventTypes.JoinRules,
            EventTypes.CanonicalAlias,
            EventTypes.RoomAvatar,
            EventTypes.RoomEncryption,
            EventTypes.Name,
        ]
        self.room_invite_state_types = config.get(
            "room_invite_state_types", default_room_state_types
        )
        self.room_knock_state_types = config.get(
            "room_knock_state_types", default_room_state_types
        )

    def generate_config_section(cls, **kwargs):
        return """\
        ## API Configuration ##

        # A list of event types that will be included in the room_invite_state
        #
        #room_invite_state_types:
        #  - "{JoinRules}"
        #  - "{CanonicalAlias}"
        #  - "{RoomAvatar}"
        #  - "{RoomEncryption}"
        #  - "{Name}"

        # A list of event types from a room that will be given to users when they
        # knock on the room. This allows clients to display information about the
        # room that they've knocked on, without actually being in the room yet.
        #
        #room_knock_state_types:
        #  - "{JoinRules}"
        #  - "{CanonicalAlias}"
        #  - "{RoomAvatar}"
        #  - "{RoomEncryption}"
        #  - "{Name}"
        """.format(
            **vars(EventTypes)
        )
