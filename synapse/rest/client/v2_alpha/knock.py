# -*- coding: utf-8 -*-
# Copyright 2020 Sorunome
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

from synapse.api.errors import AuthError, SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.types import RoomAlias, RoomID, StreamToken, ThirdPartyInstanceID, UserID

from ._base import client_patterns

logger = logging.getLogger(__name__)

class TransactionRestServlet(RestServlet):
    def __init__(self, hs):
        super(TransactionRestServlet, self).__init__()
        self.txns = HttpTransactionCache(hs)

class KnockServlet(TransactionRestServlet):
    """
    POST /rooms/{roomId}/knock
    """

    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/knock"
    )

    def __init__(self, hs):
        super(KnockServlet, self).__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    async def on_POST(self, request, room_id, txn_id=None):
        requester = await self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)
        event_content = None
        if "reason" in content:
            event_content = {"reason": content["reason"]}

        await self.room_member_handler.update_membership(
            requester=requester,
            target=requester.user,
            room_id=room_id,
            action="knock",
            txn_id=txn_id,
            third_party_signed=None,
            content=event_content,
        )

        return 200, {}

    def on_PUT(self, request, room_id, txn_id):
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, txn_id
        )

class KnockRoomALiasServlet(TransactionRestServlet):
    """
    POST /knock/{roomIdOrAlias}
    """

    PATTERNS = client_patterns(
        "/knock/(?P<room_identifier>[^/]*)"
    )

    def __init__(self, hs):
        super(KnockRoomALiasServlet, self).__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    async def on_POST(self, request, room_identifier, txn_id=None):
        requester = await self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)
        event_content = None
        if "reason" in content:
            event_content = {"reason": content["reason"]}

        if RoomID.is_valid(room_identifier):
            room_id = room_identifier
            try:
                remote_room_hosts = [
                    x.decode("ascii") for x in request.args[b"server_name"]
                ]
            except Exception:
                remote_room_hosts = None
        elif RoomAlias.is_valid(room_identifier):
            handler = self.room_member_handler
            room_alias = RoomAlias.from_string(room_identifier)
            room_id, remote_room_hosts = await handler.lookup_room_alias(room_alias)
            room_id = room_id.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )

        await self.room_member_handler.update_membership(
            requester=requester,
            target=requester.user,
            room_id=room_id,
            action="knock",
            txn_id=txn_id,
            third_party_signed=None,
            remote_room_hosts=remote_room_hosts,
            content=event_content,
        )

        return 200, {}

    def on_PUT(self, request, room_identifier, txn_id):
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_identifier, txn_id
        )

def register_servlets(hs, http_server):
    KnockServlet(hs).register(http_server)
    KnockRoomALiasServlet(hs).register(http_server)
