# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.constants import EventTypes


class ApiConfig(Config):

    def read_config(self, config):
        self.room_invite_state_types = config.get("room_invite_state_types", [
            EventTypes.JoinRules,
            EventTypes.CanonicalAlias,
            EventTypes.RoomAvatar,
            EventTypes.Name,
        ])

    def default_config(cls, **kwargs):
        return """\
        ## API Configuration ##

        # A list of event types that will be included in the room_invite_state
        room_invite_state_types:
            - "{JoinRules}"
            - "{CanonicalAlias}"
            - "{RoomAvatar}"
            - "{Name}"
        """.format(**vars(EventTypes))
