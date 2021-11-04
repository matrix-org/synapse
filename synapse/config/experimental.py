# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from synapse.config._base import Config
from synapse.types import JsonDict


class ExperimentalConfig(Config):
    """Config section for enabling experimental features"""

    section = "experimental"

    def read_config(self, config: JsonDict, **kwargs):
        experimental = config.get("experimental_features") or {}

        # Whether to enable experimental MSC1849 (aka relations) support
        self.msc1849_enabled = config.get("experimental_msc1849_support_enabled", True)
        # MSC3440 (thread relation)
        self.msc3440_enabled: bool = experimental.get("msc3440_enabled", False)

        # MSC3026 (busy presence state)
        self.msc3026_enabled: bool = experimental.get("msc3026_enabled", False)

        # MSC2716 (backfill existing history)
        self.msc2716_enabled: bool = experimental.get("msc2716_enabled", False)

        # MSC2285 (hidden read receipts)
        self.msc2285_enabled: bool = experimental.get("msc2285_enabled", False)

        # MSC3244 (room version capabilities)
        self.msc3244_enabled: bool = experimental.get("msc3244_enabled", True)

        # MSC3283 (set displayname, avatar_url and change 3pid capabilities)
        self.msc3283_enabled: bool = experimental.get("msc3283_enabled", False)

        # MSC3266 (room summary api)
        self.msc3266_enabled: bool = experimental.get("msc3266_enabled", False)

        # MSC2409 (this setting only relates to optionally sending to-device messages).
        # Presence, typing and read receipt EDUs are already sent to application services that
        # have opted in to receive them. This setting, if enabled, adds to-device messages
        # to that list.
        self.msc2409_to_device_messages_enabled: bool = experimental.get(
            "msc2409_to_device_messages_enabled", False
        )
