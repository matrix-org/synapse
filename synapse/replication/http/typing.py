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

from synapse.types import Requester, UserID
from typing import TYPE_CHECKING
import logging

from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationTypingRestServlet(ReplicationEndpoint):
    """Call to start or stop a user typing in a room.

    Request format:

        POST /_synapse/replication/typing/:room_id/:user_id

        {
            "requester": ...,
            "typing": true,
            "timeout": 30000
        }

    """

    NAME = "typing"
    PATH_ARGS = ("room_id", "user_id")
    CACHE = False

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.handler = hs.get_typing_handler()
        self.store = hs.get_datastore()

    @staticmethod
    async def _serialize_payload(requester, room_id, user_id, typing, timeout):
        payload = {
            "requester": requester.serialize(),
            "typing": typing,
            "timeout": timeout,
        }

        return payload

    async def _handle_request(self, request, room_id, user_id):
        content = parse_json_object_from_request(request)

        requester = Requester.deserialize(self.store, content["requester"])
        request.requester = requester

        target_user = UserID.from_string(user_id)

        if content["typing"]:
            await self.handler.started_typing(
                target_user,
                requester,
                room_id,
                content["timeout"],
            )
        else:
            await self.handler.stopped_typing(
                target_user,
                requester,
                room_id,
            )

        return 200, {}


def register_servlets(hs, http_server):
    ReplicationTypingRestServlet(hs).register(http_server)
