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

import logging
from collections import namedtuple
from typing import List, Tuple

from synapse.api.errors import AuthError, SynapseError
from synapse.logging.context import run_in_background
from synapse.types import UserID, get_domain_from_id
from synapse.util.caches.stream_change_cache import StreamChangeCache
from synapse.util.metrics import Measure
from synapse.util.wheel_timer import WheelTimer

logger = logging.getLogger(__name__)


# A tiny object useful for storing a user's membership in a room, as a mapping
# key
RoomMember = namedtuple("RoomMember", ("room_id", "user_id"))


# How often we expect remote servers to resend us presence.
FEDERATION_TIMEOUT = 60 * 1000

# How often to resend typing across federation.
FEDERATION_PING_INTERVAL = 40 * 1000


class TypingHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.server_name = hs.config.server_name
        self.auth = hs.get_auth()
        self.is_mine_id = hs.is_mine_id
        self.notifier = hs.get_notifier()
        self.state = hs.get_state_handler()

        self.hs = hs

        self.clock = hs.get_clock()
        self.wheel_timer = WheelTimer(bucket_size=5000)

        self.federation = hs.get_federation_sender()

        hs.get_federation_registry().register_edu_handler("m.typing", self._recv_edu)

        hs.get_distributor().observe("user_left_room", self.user_left_room)

        self._member_typing_until = {}  # clock time we expect to stop
        self._member_last_federation_poke = {}

        self._latest_room_serial = 0
        self._reset()

        # caches which room_ids changed at which serials
        self._typing_stream_change_cache = StreamChangeCache(
            "TypingStreamChangeCache", self._latest_room_serial
        )

        self.clock.looping_call(self._handle_timeouts, 5000)

    def _reset(self):
        """
        Reset the typing handler's data caches.
        """
        # map room IDs to serial numbers
        self._room_serials = {}
        # map room IDs to sets of users currently typing
        self._room_typing = {}

    def _handle_timeouts(self):
        logger.debug("Checking for typing timeouts")

        now = self.clock.time_msec()

        members = set(self.wheel_timer.fetch(now))

        for member in members:
            if not self.is_typing(member):
                # Nothing to do if they're no longer typing
                continue

            until = self._member_typing_until.get(member, None)
            if not until or until <= now:
                logger.info("Timing out typing for: %s", member.user_id)
                self._stopped_typing(member)
                continue

            # Check if we need to resend a keep alive over federation for this
            # user.
            if self.hs.is_mine_id(member.user_id):
                last_fed_poke = self._member_last_federation_poke.get(member, None)
                if not last_fed_poke or last_fed_poke + FEDERATION_PING_INTERVAL <= now:
                    run_in_background(self._push_remote, member=member, typing=True)

            # Add a paranoia timer to ensure that we always have a timer for
            # each person typing.
            self.wheel_timer.insert(now=now, obj=member, then=now + 60 * 1000)

    def is_typing(self, member):
        return member.user_id in self._room_typing.get(member.room_id, [])

    async def started_typing(self, target_user, auth_user, room_id, timeout):
        target_user_id = target_user.to_string()
        auth_user_id = auth_user.to_string()

        if not self.is_mine_id(target_user_id):
            raise SynapseError(400, "User is not hosted on this homeserver")

        if target_user_id != auth_user_id:
            raise AuthError(400, "Cannot set another user's typing state")

        await self.auth.check_user_in_room(room_id, target_user_id)

        logger.debug("%s has started typing in %s", target_user_id, room_id)

        member = RoomMember(room_id=room_id, user_id=target_user_id)

        was_present = member.user_id in self._room_typing.get(room_id, set())

        now = self.clock.time_msec()
        self._member_typing_until[member] = now + timeout

        self.wheel_timer.insert(now=now, obj=member, then=now + timeout)

        if was_present:
            # No point sending another notification
            return None

        self._push_update(member=member, typing=True)

    async def stopped_typing(self, target_user, auth_user, room_id):
        target_user_id = target_user.to_string()
        auth_user_id = auth_user.to_string()

        if not self.is_mine_id(target_user_id):
            raise SynapseError(400, "User is not hosted on this homeserver")

        if target_user_id != auth_user_id:
            raise AuthError(400, "Cannot set another user's typing state")

        await self.auth.check_user_in_room(room_id, target_user_id)

        logger.debug("%s has stopped typing in %s", target_user_id, room_id)

        member = RoomMember(room_id=room_id, user_id=target_user_id)

        self._stopped_typing(member)

    def user_left_room(self, user, room_id):
        user_id = user.to_string()
        if self.is_mine_id(user_id):
            member = RoomMember(room_id=room_id, user_id=user_id)
            self._stopped_typing(member)

    def _stopped_typing(self, member):
        if member.user_id not in self._room_typing.get(member.room_id, set()):
            # No point
            return None

        self._member_typing_until.pop(member, None)
        self._member_last_federation_poke.pop(member, None)

        self._push_update(member=member, typing=False)

    def _push_update(self, member, typing):
        if self.hs.is_mine_id(member.user_id):
            # Only send updates for changes to our own users.
            run_in_background(self._push_remote, member, typing)

        self._push_update_local(member=member, typing=typing)

    async def _push_remote(self, member, typing):
        try:
            users = await self.state.get_current_users_in_room(member.room_id)
            self._member_last_federation_poke[member] = self.clock.time_msec()

            now = self.clock.time_msec()
            self.wheel_timer.insert(
                now=now, obj=member, then=now + FEDERATION_PING_INTERVAL
            )

            for domain in {get_domain_from_id(u) for u in users}:
                if domain != self.server_name:
                    logger.debug("sending typing update to %s", domain)
                    self.federation.build_and_send_edu(
                        destination=domain,
                        edu_type="m.typing",
                        content={
                            "room_id": member.room_id,
                            "user_id": member.user_id,
                            "typing": typing,
                        },
                        key=member,
                    )
        except Exception:
            logger.exception("Error pushing typing notif to remotes")

    async def _recv_edu(self, origin, content):
        room_id = content["room_id"]
        user_id = content["user_id"]

        member = RoomMember(user_id=user_id, room_id=room_id)

        # Check that the string is a valid user id
        user = UserID.from_string(user_id)

        if user.domain != origin:
            logger.info(
                "Got typing update from %r with bad 'user_id': %r", origin, user_id
            )
            return

        users = await self.state.get_current_users_in_room(room_id)
        domains = {get_domain_from_id(u) for u in users}

        if self.server_name in domains:
            logger.info("Got typing update from %s: %r", user_id, content)
            now = self.clock.time_msec()
            self._member_typing_until[member] = now + FEDERATION_TIMEOUT
            self.wheel_timer.insert(now=now, obj=member, then=now + FEDERATION_TIMEOUT)
            self._push_update_local(member=member, typing=content["typing"])

    def _push_update_local(self, member, typing):
        room_set = self._room_typing.setdefault(member.room_id, set())
        if typing:
            room_set.add(member.user_id)
        else:
            room_set.discard(member.user_id)

        self._latest_room_serial += 1
        self._room_serials[member.room_id] = self._latest_room_serial
        self._typing_stream_change_cache.entity_has_changed(
            member.room_id, self._latest_room_serial
        )

        self.notifier.on_new_event(
            "typing_key", self._latest_room_serial, rooms=[member.room_id]
        )

    async def get_all_typing_updates(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, list]], int, bool]:
        """Get updates for typing replication stream.

        Args:
            instance_name: The writer we want to fetch updates from. Unused
                here since there is only ever one writer.
            last_id: The token to fetch updates from. Exclusive.
            current_id: The token to fetch updates up to. Inclusive.
            limit: The requested limit for the number of rows to return. The
                function may return more or fewer rows.

        Returns:
            A tuple consisting of: the updates, a token to use to fetch
            subsequent updates, and whether we returned fewer rows than exists
            between the requested tokens due to the limit.

            The token returned can be used in a subsequent call to this
            function to get further updatees.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        if last_id == current_id:
            return [], current_id, False

        changed_rooms = self._typing_stream_change_cache.get_all_entities_changed(
            last_id
        )

        if changed_rooms is None:
            changed_rooms = self._room_serials

        rows = []
        for room_id in changed_rooms:
            serial = self._room_serials[room_id]
            if last_id < serial <= current_id:
                typing = self._room_typing[room_id]
                rows.append((serial, [room_id, list(typing)]))
        rows.sort()

        limited = False
        # We, unusually, use a strict limit here as we have all the rows in
        # memory rather than pulling them out of the database with a `LIMIT ?`
        # clause.
        if len(rows) > limit:
            rows = rows[:limit]
            current_id = rows[-1][0]
            limited = True

        return rows, current_id, limited

    def get_current_token(self):
        return self._latest_room_serial


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
            "content": {"user_ids": list(typing)},
        }

    async def get_new_events(self, from_key, room_ids, **kwargs):
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

            return (events, handler._latest_room_serial)

    def get_current_key(self):
        return self.get_typing_handler()._latest_room_serial
