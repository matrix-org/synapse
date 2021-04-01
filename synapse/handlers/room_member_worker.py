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
from typing import TYPE_CHECKING, List, Optional, Tuple

from synapse.api.errors import SynapseError
from synapse.handlers.room_member import RoomMemberHandler
from synapse.replication.http.membership import (
    ReplicationRemoteJoinRestServlet as ReplRemoteJoin,
    ReplicationRemoteRejectInviteRestServlet as ReplRejectInvite,
    ReplicationUserJoinedLeftRoomRestServlet as ReplJoinedLeft,
)
from synapse.types import Requester, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RoomMemberWorkerHandler(RoomMemberHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._remote_join_client = ReplRemoteJoin.make_client(hs)
        self._remote_reject_client = ReplRejectInvite.make_client(hs)
        self._notify_change_client = ReplJoinedLeft.make_client(hs)

    async def _remote_join(
        self,
        requester: Requester,
        remote_room_hosts: List[str],
        room_id: str,
        user: UserID,
        content: dict,
    ) -> Tuple[str, int]:
        """Implements RoomMemberHandler._remote_join"""
        if len(remote_room_hosts) == 0:
            raise SynapseError(404, "No known servers")

        ret = await self._remote_join_client(
            requester=requester,
            remote_room_hosts=remote_room_hosts,
            room_id=room_id,
            user_id=user.to_string(),
            content=content,
        )

        return ret["event_id"], ret["stream_id"]

    async def remote_reject_invite(
        self,
        invite_event_id: str,
        txn_id: Optional[str],
        requester: Requester,
        content: dict,
    ) -> Tuple[str, int]:
        """
        Rejects an out-of-band invite received from a remote user

        Implements RoomMemberHandler.remote_reject_invite
        """
        ret = await self._remote_reject_client(
            invite_event_id=invite_event_id,
            txn_id=txn_id,
            requester=requester,
            content=content,
        )
        return ret["event_id"], ret["stream_id"]

    async def _user_left_room(self, target: UserID, room_id: str) -> None:
        """Implements RoomMemberHandler._user_left_room"""
        await self._notify_change_client(
            user_id=target.to_string(), room_id=room_id, change="left"
        )

    async def forget(self, target: UserID, room_id: str) -> None:
        raise RuntimeError("Cannot forget rooms on workers.")
