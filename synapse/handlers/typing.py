# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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
from synapse.types import UserID

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

        hs.get_distributor().observe("user_left_room", self.user_left_room)

        self._member_typing_until = {}  # clock time we expect to stop
        self._member_typing_timer = {}  # deferreds to manage theabove

        # map room IDs to serial numbers
        self._room_serials = {}
        self._latest_room_serial = 0
        # map room IDs to sets of users currently typing
        self._room_typing = {}

    def tearDown(self):
        """Cancels all the pending timers.
        Normally this shouldn't be needed, but it's required from unit tests
        to avoid a "Reactor was unclean" warning."""
        for t in self._member_typing_timer.values():
            self.clock.cancel_call_later(t)

    @defer.inlineCallbacks
    def started_typing(self, target_user, auth_user, room_id, timeout):
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's typing state")

        yield self.auth.check_joined_room(room_id, target_user.to_string())

        logger.debug(
            "%s has started typing in %s", target_user.to_string(), room_id
        )

        until = self.clock.time_msec() + timeout
        member = RoomMember(room_id=room_id, user=target_user)

        was_present = member in self._member_typing_until

        if member in self._member_typing_timer:
            self.clock.cancel_call_later(self._member_typing_timer[member])

        def _cb():
            logger.debug(
                "%s has timed out in %s", target_user.to_string(), room_id
            )
            self._stopped_typing(member)

        self._member_typing_until[member] = until
        self._member_typing_timer[member] = self.clock.call_later(
            timeout / 1000.0, _cb
        )

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
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's typing state")

        yield self.auth.check_joined_room(room_id, target_user.to_string())

        logger.debug(
            "%s has stopped typing in %s", target_user.to_string(), room_id
        )

        member = RoomMember(room_id=room_id, user=target_user)

        if member in self._member_typing_timer:
            self.clock.cancel_call_later(self._member_typing_timer[member])
            del self._member_typing_timer[member]

        yield self._stopped_typing(member)

    @defer.inlineCallbacks
    def user_left_room(self, user, room_id):
        if self.hs.is_mine(user):
            member = RoomMember(room_id=room_id, user=user)
            yield self._stopped_typing(member)

    @defer.inlineCallbacks
    def _stopped_typing(self, member):
        if member not in self._member_typing_until:
            # No point
            defer.returnValue(None)

        yield self._push_update(
            room_id=member.room_id,
            user=member.user,
            typing=False,
        )

        del self._member_typing_until[member]

        if member in self._member_typing_timer:
            # Don't cancel it - either it already expired, or the real
            # stopped_typing() will cancel it
            del self._member_typing_timer[member]

    @defer.inlineCallbacks
    def _push_update(self, room_id, user, typing):
        localusers = set()
        remotedomains = set()

        rm_handler = self.homeserver.get_handlers().room_member_handler
        yield rm_handler.fetch_room_distributions_into(
            room_id, localusers=localusers, remotedomains=remotedomains
        )

        if localusers:
            self._push_update_local(
                room_id=room_id,
                user=user,
                typing=typing
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

        yield defer.DeferredList(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    def _recv_edu(self, origin, content):
        room_id = content["room_id"]
        user = UserID.from_string(content["user_id"])

        localusers = set()

        rm_handler = self.homeserver.get_handlers().room_member_handler
        yield rm_handler.fetch_room_distributions_into(
            room_id, localusers=localusers
        )

        if localusers:
            self._push_update_local(
                room_id=room_id,
                user=user,
                typing=content["typing"]
            )

    def _push_update_local(self, room_id, user, typing):
        if room_id not in self._room_serials:
            self._room_serials[room_id] = 0
            self._room_typing[room_id] = set()

        room_set = self._room_typing[room_id]
        if typing:
            room_set.add(user)
        elif user in room_set:
            room_set.remove(user)

        self._latest_room_serial += 1
        self._room_serials[room_id] = self._latest_room_serial

        self.notifier.on_new_user_event(rooms=[room_id])


class TypingNotificationEventSource(object):
    def __init__(self, hs):
        self.hs = hs
        self._handler = None

    def handler(self):
        # Avoid cyclic dependency in handler setup
        if not self._handler:
            self._handler = self.hs.get_handlers().typing_notification_handler
        return self._handler

    def _make_event_for(self, room_id):
        typing = self.handler()._room_typing[room_id]
        return {
            "type": "m.typing",
            "room_id": room_id,
            "content": {
                "user_ids": [u.to_string() for u in typing],
            },
        }

    def get_new_events_for_user(self, user, from_key, limit):
        from_key = int(from_key)
        handler = self.handler()

        events = []
        for room_id in handler._room_serials:
            if handler._room_serials[room_id] <= from_key:
                continue

            # TODO: check if user is in room
            events.append(self._make_event_for(room_id))

        return (events, handler._latest_room_serial)

    def get_current_key(self):
        return self.handler()._latest_room_serial

    def get_pagination_rows(self, user, pagination_config, key):
        return ([], pagination_config.from_key)
