# -*- coding: utf-8 -*-
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

import logging
from typing import TYPE_CHECKING, Optional

from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict, Requester, UserID
from synapse.util.distributor import user_left_room

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationRemoteJoinRestServlet(ReplicationEndpoint):
    """Does a remote join for the given user to the given room

    Request format:

        POST /_synapse/replication/remote_join/:room_id/:user_id

        {
            "requester": ...,
            "remote_room_hosts": [...],
            "content": { ... }
        }
    """

    NAME = "remote_join"
    PATH_ARGS = ("room_id", "user_id")

    def __init__(self, hs):
        super().__init__(hs)

        self.federation_handler = hs.get_handlers().federation_handler
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @staticmethod
    async def _serialize_payload(
        requester, room_id, user_id, remote_room_hosts, content
    ):
        """
        Args:
            requester(Requester)
            room_id (str)
            user_id (str)
            remote_room_hosts (list[str]): Servers to try and join via
            content(dict): The event content to use for the join event
        """
        return {
            "requester": requester.serialize(),
            "remote_room_hosts": remote_room_hosts,
            "content": content,
        }

    async def _handle_request(self, request, room_id, user_id):
        content = parse_json_object_from_request(request)

        remote_room_hosts = content["remote_room_hosts"]
        event_content = content["content"]

        requester = Requester.deserialize(self.store, content["requester"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        logger.info("remote_join: %s into room: %s", user_id, room_id)

        event_id, stream_id = await self.federation_handler.do_invite_join(
            remote_room_hosts, room_id, user_id, event_content
        )

        return 200, {"event_id": event_id, "stream_id": stream_id}


class ReplicationRemoteRejectInviteRestServlet(ReplicationEndpoint):
    """Rejects an out-of-band invite we have received from a remote server

    Request format:

        POST /_synapse/replication/remote_reject_invite/:event_id

        {
            "txn_id": ...,
            "requester": ...,
            "content": { ... }
        }
    """

    NAME = "remote_reject_invite"
    PATH_ARGS = ("invite_event_id",)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.member_handler = hs.get_room_member_handler()

    @staticmethod
    async def _serialize_payload(  # type: ignore
        invite_event_id: str,
        txn_id: Optional[str],
        requester: Requester,
        content: JsonDict,
    ):
        """
        Args:
            invite_event_id: ID of the invite to be rejected
            txn_id: optional transaction ID supplied by the client
            requester: user making the rejection request, according to the access token
            content: additional content to include in the rejection event.
               Normally an empty dict.
        """
        return {
            "txn_id": txn_id,
            "requester": requester.serialize(),
            "content": content,
        }

    async def _handle_request(self, request, invite_event_id):
        content = parse_json_object_from_request(request)

        txn_id = content["txn_id"]
        event_content = content["content"]

        requester = Requester.deserialize(self.store, content["requester"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        # hopefully we're now on the master, so this won't recurse!
        event_id, stream_id = await self.member_handler.remote_reject_invite(
            invite_event_id, txn_id, requester, event_content,
        )

        return 200, {"event_id": event_id, "stream_id": stream_id}


class ReplicationUserJoinedLeftRoomRestServlet(ReplicationEndpoint):
    """Notifies that a user has joined or left the room

    Request format:

        POST /_synapse/replication/membership_change/:room_id/:user_id/:change

        {}
    """

    NAME = "membership_change"
    PATH_ARGS = ("room_id", "user_id", "change")
    CACHE = False  # No point caching as should return instantly.

    def __init__(self, hs):
        super().__init__(hs)

        self.registeration_handler = hs.get_registration_handler()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.distributor = hs.get_distributor()

    @staticmethod
    async def _serialize_payload(room_id, user_id, change):
        """
        Args:
            room_id (str)
            user_id (str)
            change (str): "left"
        """
        assert change == "left"

        return {}

    def _handle_request(self, request, room_id, user_id, change):
        logger.info("user membership change: %s in %s", user_id, room_id)

        user = UserID.from_string(user_id)

        if change == "left":
            user_left_room(self.distributor, user, room_id)
        else:
            raise Exception("Unrecognized change: %r", change)

        return 200, {}


def register_servlets(hs, http_server):
    ReplicationRemoteJoinRestServlet(hs).register(http_server)
    ReplicationRemoteRejectInviteRestServlet(hs).register(http_server)
    ReplicationUserJoinedLeftRoomRestServlet(hs).register(http_server)
