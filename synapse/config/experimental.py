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

import attr

from synapse.config._base import Config
from synapse.types import JsonDict


@attr.s(auto_attribs=True, frozen=True, slots=True)
class MSC3866Config:
    """Configuration for MSC3866 (mandating approval for new users)"""

    # Whether the base support for the approval process is enabled. This includes the
    # ability for administrators to check and update the approval of users, even if no
    # approval is currently required.
    enabled: bool = False
    # Whether to require that new users are approved by an admin before their account
    # can be used. Note that this setting is ignored if 'enabled' is false.
    require_approval_for_new_accounts: bool = False


class ExperimentalConfig(Config):
    """Config section for enabling experimental features"""

    section = "experimental"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        experimental = config.get("experimental_features") or {}

        # MSC3026 (busy presence state)
        self.msc3026_enabled: bool = experimental.get("msc3026_enabled", False)

        # MSC2716 (importing historical messages)
        self.msc2716_enabled: bool = experimental.get("msc2716_enabled", False)

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

        # experimental support for faster joins over federation
        # (MSC2775, MSC3706, MSC3895)
        # requires a target server with msc3706_enabled enabled.
        self.faster_joins_enabled: bool = experimental.get("faster_joins", False)

        # MSC3720 (Account status endpoint)
        self.msc3720_enabled: bool = experimental.get("msc3720_enabled", False)

        # MSC2654: Unread counts
        #
        # Note that enabling this will result in an incorrect unread count for
        # previously calculated push actions.
        self.msc2654_enabled: bool = experimental.get("msc2654_enabled", False)

        # MSC2815 (allow room moderators to view redacted event content)
        self.msc2815_enabled: bool = experimental.get("msc2815_enabled", False)

        # MSC3786 (Add a default push rule to ignore m.room.server_acl events)
        self.msc3786_enabled: bool = experimental.get("msc3786_enabled", False)

        # MSC3771: Thread read receipts
        self.msc3771_enabled: bool = experimental.get("msc3771_enabled", False)
        # MSC3772: A push rule for mutual relations.
        self.msc3772_enabled: bool = experimental.get("msc3772_enabled", False)

        # MSC3715: dir param on /relations.
        self.msc3715_enabled: bool = experimental.get("msc3715_enabled", False)

        # MSC3848: Introduce errcodes for specific event sending failures
        self.msc3848_enabled: bool = experimental.get("msc3848_enabled", False)

        # MSC3852: Expose last seen user agent field on /_matrix/client/v3/devices.
        self.msc3852_enabled: bool = experimental.get("msc3852_enabled", False)

        # MSC3866: M_USER_AWAITING_APPROVAL error code
        raw_msc3866_config = experimental.get("msc3866", {})
        self.msc3866 = MSC3866Config(**raw_msc3866_config)

        # MSC3881: Remotely toggle push notifications for another client
        self.msc3881_enabled: bool = experimental.get("msc3881_enabled", False)

        # MSC3882: Allow an existing session to sign in a new session
        self.msc3882_enabled: bool = experimental.get("msc3882_enabled", False)
        self.msc3882_ui_auth: bool = experimental.get("msc3882_ui_auth", True)
        self.msc3882_token_timeout = self.parse_duration(
            experimental.get("msc3882_token_timeout", "5m")
        )
