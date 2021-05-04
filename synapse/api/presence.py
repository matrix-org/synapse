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

from collections import namedtuple

from synapse.api.constants import PresenceState


class UserPresenceState(
    namedtuple(
        "UserPresenceState",
        (
            "user_id",
            "state",
            "last_active_ts",
            "last_federation_update_ts",
            "last_user_sync_ts",
            "status_msg",
            "currently_active",
        ),
    )
):
    """Represents the current presence state of the user.

    user_id (str)
    last_active (int): Time in msec that the user last interacted with server.
    last_federation_update (int): Time in msec since either a) we sent a presence
        update to other servers or b) we received a presence update, depending
        on if is a local user or not.
    last_user_sync (int): Time in msec that the user last *completed* a sync
        (or event stream).
    status_msg (str): User set status message.
    """

    def as_dict(self):
        return dict(self._asdict())

    @staticmethod
    def from_dict(d):
        return UserPresenceState(**d)

    def copy_and_replace(self, **kwargs):
        return self._replace(**kwargs)

    @classmethod
    def default(cls, user_id):
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
