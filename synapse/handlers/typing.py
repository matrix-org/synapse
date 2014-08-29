# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from twisted.internet import defer

from ._base import BaseHandler

from synapse.api.errors import SynapseError, AuthError

import logging

from collections import namedtuple

logger = logging.getLogger(__name__)


# A tiny object useful for storing a user's membership in a room, as a mapping
# key
RoomMember = namedtuple("RoomMember", ("room_id", "user"))


class TypingNotificationHandler(BaseHandler):
    def __init__(self, hs):
        super(TypingNotificationHandler, self).__init__(hs)

        self.homeserver = hs

        self.clock = hs.get_clock()

        self.federation = hs.get_replication_layer()

        self.federation.register_edu_handler("m.typing", self._recv_edu)

        self._member_typing_until = {}

    @defer.inlineCallbacks
    def started_typing(self, target_user, auth_user, room_id, timeout):
        if not target_user.is_mine:
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's typing state")

        until = self.clock.time_msec() + timeout
        member = RoomMember(room_id=room_id, user=target_user)

        was_present = member in self._member_typing_until

        self._member_typing_until[member] = until

        if was_present:
            # No point sending another notification
            defer.returnValue(None)

        yield self._push_update(
            room_id=room_id,
            user=target_user,
            typing=True,
        )

    @defer.inlineCallbacks
    def stopped_typing(self, target_user, auth_user, room_id):
        if not target_user.is_mine:
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's typing state")

        member = RoomMember(room_id=room_id, user=target_user)

        if member not in self._member_typing_until:
            # No point
            defer.returnValue(None)

        yield self._push_update(
            room_id=room_id,
            user=target_user,
            typing=False,
        )

    @defer.inlineCallbacks
    def _push_update(self, room_id, user, typing):
        localusers = set()
        remotedomains = set()

        rm_handler = self.homeserver.get_handlers().room_member_handler
        yield rm_handler.fetch_room_distributions_into(room_id,
                localusers=localusers, remotedomains=remotedomains,
                ignore_user=user)

        for u in localusers:
            self.push_update_to_clients(
                room_id=room_id,
                observer_user=u,
                observed_user=user,
                typing=typing,
            )

        deferreds = []
        for domain in remotedomains:
            deferreds.append(self.federation.send_edu(
                destination=domain,
                edu_type="m.typing",
                content={
                    "room_id": room_id,
                    "user_id": user.to_string(),
                    "typing": typing,
                },
            ))

        yield defer.DeferredList(deferreds, consumeErrors=False)

    @defer.inlineCallbacks
    def _recv_edu(self, origin, content):
        room_id = content["room_id"]
        user = self.homeserver.parse_userid(content["user_id"])

        localusers = set()

        rm_handler = self.homeserver.get_handlers().room_member_handler
        yield rm_handler.fetch_room_distributions_into(room_id,
                localusers=localusers)

        for u in localusers:
            self.push_update_to_clients(
                room_id=room_id,
                observer_user=u,
                observed_user=user,
                typing=content["typing"]
            )

    def push_update_to_clients(self, room_id, observer_user, observed_user,
            typing):
        # TODO(paul) steal this from presence.py
        pass


class TypingNotificationEventSource(object):
    def __init__(self, hs):
        self.hs = hs

    def get_new_events_for_user(self, user, from_key, limit):
        return ([], from_key)

    def get_current_token_part(self):
        return 0

    def get_pagination_rows(self, user, pagination_config, key):
        return ([], pagination_config.from_token)
