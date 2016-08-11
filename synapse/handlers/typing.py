# -*- coding: utf-8 -*-
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

from twisted.internet import defer

from synapse.api.errors import SynapseError, AuthError
from synapse.util.logcontext import PreserveLoggingContext
from synapse.util.metrics import Measure
from synapse.types import UserID

import logging

from collections import namedtuple
import ujson as json

logger = logging.getLogger(__name__)


# A tiny object useful for storing a user's membership in a room, as a mapping
# key
RoomMember = namedtuple("RoomMember", ("room_id", "user_id"))


class TypingHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.server_name = hs.config.server_name
        self.auth = hs.get_auth()
        self.is_mine_id = hs.is_mine_id
        self.notifier = hs.get_notifier()

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
        target_user_id = target_user.to_string()
        auth_user_id = auth_user.to_string()

        if not self.is_mine_id(target_user_id):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user_id != auth_user_id:
            raise AuthError(400, "Cannot set another user's typing state")

        yield self.auth.check_joined_room(room_id, target_user_id)

        logger.debug(
            "%s has started typing in %s", target_user_id, room_id
        )

        until = self.clock.time_msec() + timeout
        member = RoomMember(room_id=room_id, user_id=target_user_id)

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
            user_id=target_user_id,
            typing=True,
        )

    @defer.inlineCallbacks
    def stopped_typing(self, target_user, auth_user, room_id):
        target_user_id = target_user.to_string()
        auth_user_id = auth_user.to_string()

        if not self.is_mine_id(target_user_id):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user_id != auth_user_id:
            raise AuthError(400, "Cannot set another user's typing state")

        yield self.auth.check_joined_room(room_id, target_user_id)

        logger.debug(
            "%s has stopped typing in %s", target_user_id, room_id
        )

        member = RoomMember(room_id=room_id, user_id=target_user_id)

        if member in self._member_typing_timer:
            self.clock.cancel_call_later(self._member_typing_timer[member])
            del self._member_typing_timer[member]

        yield self._stopped_typing(member)

    @defer.inlineCallbacks
    def user_left_room(self, user, room_id):
        user_id = user.to_string()
        if self.is_mine_id(user_id):
            member = RoomMember(room_id=room_id, user_id=user_id)
            yield self._stopped_typing(member)

    @defer.inlineCallbacks
    def _stopped_typing(self, member):
        if member not in self._member_typing_until:
            # No point
            defer.returnValue(None)

        yield self._push_update(
            room_id=member.room_id,
            user_id=member.user_id,
            typing=False,
        )

        del self._member_typing_until[member]

        if member in self._member_typing_timer:
            # Don't cancel it - either it already expired, or the real
            # stopped_typing() will cancel it
            del self._member_typing_timer[member]

    @defer.inlineCallbacks
    def _push_update(self, room_id, user_id, typing):
        domains = yield self.store.get_joined_hosts_for_room(room_id)

        deferreds = []
        for domain in domains:
            if domain == self.server_name:
                self._push_update_local(
                    room_id=room_id,
                    user_id=user_id,
                    typing=typing
                )
            else:
                deferreds.append(self.federation.send_edu(
                    destination=domain,
                    edu_type="m.typing",
                    content={
                        "room_id": room_id,
                        "user_id": user_id,
                        "typing": typing,
                    },
                ))

        yield defer.DeferredList(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    def _recv_edu(self, origin, content):
        room_id = content["room_id"]
        user_id = content["user_id"]

        # Check that the string is a valid user id
        UserID.from_string(user_id)

        domains = yield self.store.get_joined_hosts_for_room(room_id)

        if self.server_name in domains:
            self._push_update_local(
                room_id=room_id,
                user_id=user_id,
                typing=content["typing"]
            )

    def _push_update_local(self, room_id, user_id, typing):
        room_set = self._room_typing.setdefault(room_id, set())
        if typing:
            room_set.add(user_id)
        else:
            room_set.discard(user_id)

        self._latest_room_serial += 1
        self._room_serials[room_id] = self._latest_room_serial

        with PreserveLoggingContext():
            self.notifier.on_new_event(
                "typing_key", self._latest_room_serial, rooms=[room_id]
            )

    def get_all_typing_updates(self, last_id, current_id):
        # TODO: Work out a way to do this without scanning the entire state.
        if last_id == current_id:
            return []

        rows = []
        for room_id, serial in self._room_serials.items():
            if last_id < serial and serial <= current_id:
                typing = self._room_typing[room_id]
                typing_bytes = json.dumps(list(typing), ensure_ascii=False)
                rows.append((serial, room_id, typing_bytes))
        rows.sort()
        return rows


class TypingNotificationEventSource(object):
    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()
        # We can't call get_typing_handler here because there's a cycle:
        #
        #   Typing -> Notifier -> TypingNotificationEventSource -> Typing
        #
        self.get_typing_handler = hs.get_typing_handler

    def _make_event_for(self, room_id):
        typing = self.get_typing_handler()._room_typing[room_id]
        return {
            "type": "m.typing",
            "room_id": room_id,
            "content": {
                "user_ids": list(typing),
            },
        }

    def get_new_events(self, from_key, room_ids, **kwargs):
        with Measure(self.clock, "typing.get_new_events"):
            from_key = int(from_key)
            handler = self.get_typing_handler()

            events = []
            for room_id in room_ids:
                if room_id not in handler._room_serials:
                    continue
                if handler._room_serials[room_id] <= from_key:
                    continue

                events.append(self._make_event_for(room_id))

            return events, handler._latest_room_serial

    def get_current_key(self):
        return self.get_typing_handler()._latest_room_serial

    def get_pagination_rows(self, user, pagination_config, key):
        return ([], pagination_config.from_key)
