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

from typing import Any

from synapse.config._base import Config
from synapse.types import JsonDict


class ExperimentalConfig(Config):
    """Config section for enabling experimental features"""

    section = "experimental"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        experimental = config.get("experimental_features") or {}

        # MSC3026 (busy presence state)
        self.msc3026_enabled: bool = experimental.get("msc3026_enabled", False)

        # MSC2716 (importing historical messages)
        self.msc2716_enabled: bool = experimental.get("msc2716_enabled", False)

        # MSC2285 (private read receipts)
        self.msc2285_enabled: bool = experimental.get("msc2285_enabled", False)

        # MSC3244 (room version capabilities)
        self.msc3244_enabled: bool = experimental.get("msc3244_enabled", True)

        # MSC3266 (room summary api)
        self.msc3266_enabled: bool = experimental.get("msc3266_enabled", False)

        # MSC3030 (Jump to date API endpoint)
        self.msc3030_enabled: bool = experimental.get("msc3030_enabled", False)

        # MSC2409 (this setting only relates to optionally sending to-device messages).
        # Presence, typing and read receipt EDUs are already sent to application services that
        # have opted in to receive them. If enabled, this adds to-device messages to that list.
        self.msc2409_to_device_messages_enabled: bool = experimental.get(
            "msc2409_to_device_messages_enabled", False
        )

        # The portion of MSC3202 which is related to device masquerading.
        self.msc3202_device_masquerading_enabled: bool = experimental.get(
            "msc3202_device_masquerading", False
        )

        # The portion of MSC3202 related to transaction extensions:
        # sending device list changes, one-time key counts and fallback key
        # usage to application services.
        self.msc3202_transaction_extensions: bool = experimental.get(
            "msc3202_transaction_extensions", False
        )

        # MSC3706 (server-side support for partial state in /send_join responses)
        self.msc3706_enabled: bool = experimental.get("msc3706_enabled", False)

        # experimental support for faster joins over federation (msc2775, msc3706)
        # requires a target server with msc3706_enabled enabled.
        self.faster_joins_enabled: bool = experimental.get("faster_joins", False)

        # MSC3720 (Account status endpoint)
        self.msc3720_enabled: bool = experimental.get("msc3720_enabled", False)

        # MSC2654: Unread counts
        self.msc2654_enabled: bool = experimental.get("msc2654_enabled", False)

        # MSC2815 (allow room moderators to view redacted event content)
        self.msc2815_enabled: bool = experimental.get("msc2815_enabled", False)

        # MSC3786 (Add a default push rule to ignore m.room.server_acl events)
        self.msc3786_enabled: bool = experimental.get("msc3786_enabled", False)

        # MSC3772: A push rule for mutual relations.
        self.msc3772_enabled: bool = experimental.get("msc3772_enabled", False)

        # MSC3715: dir param on /relations.
        self.msc3715_enabled: bool = experimental.get("msc3715_enabled", False)

        # MSC3827: Filtering of /publicRooms by room type
        self.msc3827_enabled: bool = experimental.get("msc3827_enabled", False)
