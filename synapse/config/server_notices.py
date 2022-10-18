# Copyright 2018 New Vector Ltd
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

from synapse.types import JsonDict, UserID

from ._base import Config


class ServerNoticesConfig(Config):
    """Configuration for the server notices room.

    Attributes:
        server_notices_mxid (str|None):
            The MXID to use for server notices.
            None if server notices are not enabled.

        server_notices_mxid_display_name (str|None):
            The display name to use for the server notices user.
            None if server notices are not enabled.

        server_notices_mxid_avatar_url (str|None):
            The MXC URL for the avatar of the server notices user.
            None if server notices are not enabled.

        server_notices_room_name (str|None):
            The name to use for the server notices room.
            None if server notices are not enabled.
    """

    section = "servernotices"

    def __init__(self, *args: Any):
        super().__init__(*args)
        self.server_notices_mxid: Optional[str] = None
        self.server_notices_mxid_display_name: Optional[str] = None
        self.server_notices_mxid_avatar_url: Optional[str] = None
        self.server_notices_room_name: Optional[str] = None

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        c = config.get("server_notices")
        if c is None:
            return

        mxid_localpart = c["system_mxid_localpart"]
        self.server_notices_mxid = UserID(
            mxid_localpart, self.root.server.server_name
        ).to_string()
        self.server_notices_mxid_display_name = c.get("system_mxid_display_name", None)
        self.server_notices_mxid_avatar_url = c.get("system_mxid_avatar_url", None)
        # todo: i18n
        self.server_notices_room_name = c.get("room_name", "Server Notices")
