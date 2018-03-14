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

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.handlers.room_member import RoomMemberHandler
from synapse.replication.http.membership import (
    remote_join, remote_reject_invite, get_or_register_3pid_guest,
    notify_user_membership_change,
)


logger = logging.getLogger(__name__)


class RoomMemberWorkerHandler(RoomMemberHandler):
    @defer.inlineCallbacks
    def _remote_join(self, requester, remote_room_hosts, room_id, user, content):
        """Implements RoomMemberHandler._remote_join
        """
        if len(remote_room_hosts) == 0:
            raise SynapseError(404, "No known servers")

        ret = yield remote_join(
            self.simple_http_client,
            host=self.config.worker_replication_host,
            port=self.config.worker_replication_http_port,
            requester=requester,
            remote_room_hosts=remote_room_hosts,
            room_id=room_id,
            user_id=user.to_string(),
            content=content,
        )

        yield self._user_joined_room(user, room_id)

        defer.returnValue(ret)

    def _remote_reject_invite(self, requester, remote_room_hosts, room_id, target):
        """Implements RoomMemberHandler._remote_reject_invite
        """
        return remote_reject_invite(
            self.simple_http_client,
            host=self.config.worker_replication_host,
            port=self.config.worker_replication_http_port,
            requester=requester,
            remote_room_hosts=remote_room_hosts,
            room_id=room_id,
            user_id=target.to_string(),
        )

    def _user_joined_room(self, target, room_id):
        """Implements RoomMemberHandler._user_joined_room
        """
        return notify_user_membership_change(
            self.simple_http_client,
            host=self.config.worker_replication_host,
            port=self.config.worker_replication_http_port,
            user_id=target.to_string(),
            room_id=room_id,
            change="joined",
        )

    def _user_left_room(self, target, room_id):
        """Implements RoomMemberHandler._user_left_room
        """
        return notify_user_membership_change(
            self.simple_http_client,
            host=self.config.worker_replication_host,
            port=self.config.worker_replication_http_port,
            user_id=target.to_string(),
            room_id=room_id,
            change="left",
        )

    def get_or_register_3pid_guest(self, requester, medium, address, inviter_user_id):
        """Implements RoomMemberHandler.get_or_register_3pid_guest
        """
        return get_or_register_3pid_guest(
            self.simple_http_client,
            host=self.config.worker_replication_host,
            port=self.config.worker_replication_http_port,
            requester=requester,
            medium=medium,
            address=address,
            inviter_user_id=inviter_user_id,
        )
