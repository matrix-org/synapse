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
import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_user_is_admin
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class BackgroundUpdateEnabledRestServlet(RestServlet):
    """Allows temporarily disabling background updates"""

    PATTERNS = admin_patterns("/background_updates/enabled")

    def __init__(self, hs: "HomeServer"):
        self.group_server = hs.get_groups_server_handler()
        self.is_mine_id = hs.is_mine_id
        self.auth = hs.get_auth()

        self.data_stores = hs.get_datastores()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        # We need to check that all configured databases have updates enabled.
        # (They *should* all be in sync.)
        enabled = all(db.updates.enabled for db in self.data_stores.databases)

        return 200, {"enabled": enabled}

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        body = parse_json_object_from_request(request)

        enabled = body.get("enabled", True)

        if not isinstance(enabled, bool):
            raise SynapseError(400, "'enabled' parameter must be a boolean")

        for db in self.data_stores.databases:
            db.updates.enabled = enabled

            # If we're re-enabling them ensure that we start the background
            # process again.
            if enabled:
                db.updates.start_doing_background_updates()

        return 200, {"enabled": enabled}


class BackgroundUpdateRestServlet(RestServlet):
    """Fetch information about background updates"""

    PATTERNS = admin_patterns("/background_updates/status")

    def __init__(self, hs: "HomeServer"):
        self.group_server = hs.get_groups_server_handler()
        self.is_mine_id = hs.is_mine_id
        self.auth = hs.get_auth()

        self.data_stores = hs.get_datastores()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        # We need to check that all configured databases have updates enabled.
        # (They *should* all be in sync.)
        enabled = all(db.updates.enabled for db in self.data_stores.databases)

        current_updates = {}

        for db in self.data_stores.databases:
            update = db.updates.get_current_update()
            if not update:
                continue

            current_updates[db.name()] = {
                "name": update.name,
                "total_item_count": update.total_item_count,
                "total_duration_ms": update.total_duration_ms,
                "average_items_per_ms": update.average_items_per_ms(),
            }

        return 200, {"enabled": enabled, "current_updates": current_updates}
