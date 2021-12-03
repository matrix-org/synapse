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

from typing import Any, Optional

import attr

from synapse.api.constants import PresenceState
from synapse.types import JsonDict


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserPresenceState:
    """Represents the current presence state of the user.

    user_id
    last_active: Time in msec that the user last interacted with server.
    last_federation_update: Time in msec since either a) we sent a presence
        update to other servers or b) we received a presence update, depending
        on if is a local user or not.
    last_user_sync: Time in msec that the user last *completed* a sync
        (or event stream).
    status_msg: User set status message.
    """

    user_id: str
    state: str
    last_active_ts: int
    last_federation_update_ts: int
    last_user_sync_ts: int
    status_msg: Optional[str]
    currently_active: bool

    def as_dict(self) -> JsonDict:
        return attr.asdict(self)

    @staticmethod
    def from_dict(d: JsonDict) -> "UserPresenceState":
        return UserPresenceState(**d)

    def copy_and_replace(self, **kwargs: Any) -> "UserPresenceState":
        return attr.evolve(self, **kwargs)

    @classmethod
    def default(cls, user_id: str) -> "UserPresenceState":
        """Returns a default presence state."""
        return cls(
            user_id=user_id,
            state=PresenceState.OFFLINE,
            last_active_ts=0,
            last_federation_update_ts=0,
            last_user_sync_ts=0,
            status_msg=None,
            currently_active=False,
        )
