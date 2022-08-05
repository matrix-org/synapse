# Copyright 2014-2016 OpenMarket Ltd
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

from typing import Any

from synapse.types import JsonDict

from ._base import Config


class VoipConfig(Config):
    section = "voip"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.turn_uris = config.get("turn_uris", [])
        self.turn_shared_secret = config.get("turn_shared_secret")
        self.turn_username = config.get("turn_username")
        self.turn_password = config.get("turn_password")
        self.turn_user_lifetime = self.parse_duration(
            config.get("turn_user_lifetime", "1h")
        )
        self.turn_allow_guests = config.get("turn_allow_guests", True)
