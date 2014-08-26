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

"""Contains handlers for federation events."""

from ._base import BaseHandler

from synapse.api.events.room import InviteJoinEvent, RoomMemberEvent
from synapse.api.constants import Membership
from synapse.util.logutils import log_function

from twisted.internet import defer

import logging


logger = logging.getLogger(__name__)


class FederationHandler(BaseHandler):

    """Handles events that originated from federation."""
    def __init__(self, hs):
        super(FederationHandler, self).__init__(hs)

        self.distributor.observe(
            "user_joined_room",
            self._on_user_joined
        )

        self.waiting_for_join_list = {}

    @log_function
    @defer.inlineCallbacks
    def on_receive(self, event, is_new_state, backfilled):
        if hasattr(event, "state_key") and not is_new_state:
            logger.debug("Ignoring old state.")
            return

        target_is_mine = False
        if hasattr(event, "target_host"):
            target_is_mine = event.target_host == self.hs.hostname

        if event.type == InviteJoinEvent.TYPE:
            if not target_is_mine:
                logger.debug("Ignoring invite/join event %s", event)
                return

            # If we receive an invite/join event then we need to join the
            # sender to the given room.
            # TODO: We should probably auth this or some such
            content = event.content
            content.update({"membership": Membership.JOIN})
            new_event = self.event_factory.create_event(
                etype=RoomMemberEvent.TYPE,
                state_key=event.user_id,
                room_id=event.room_id,
                user_id=event.user_id,
                membership=Membership.JOIN,
                content=content
            )

            yield self.hs.get_handlers().room_member_handler.change_membership(
                new_event,
                True
            )

        else:
            with (yield self.room_lock.lock(event.room_id)):
                store_id = yield self.store.persist_event(event, backfilled)

            room = yield self.store.get_room(event.room_id)

            if not room:
                # Huh, let's try and get the current state
                try:
                    federation = self.hs.get_federation()
                    yield federation.get_state_for_room(
                        event.origin, event.room_id
                    )

                    hosts = yield self.store.get_joined_hosts_for_room(
                        event.room_id
                    )
                    if self.hs.hostname in hosts:
                        try:
                            yield self.store.store_room(
                                event.room_id,
                                "",
                                is_public=False
                            )
                        except:
                            pass
                except:
                    logger.exception(
                        "Failed to get current state for room %s",
                        event.room_id
                    )

            if not backfilled:
                yield self.notifier.on_new_room_event(event, store_id)

        if event.type == RoomMemberEvent.TYPE:
            if event.membership == Membership.JOIN:
                user = self.hs.parse_userid(event.target_user_id)
                self.distributor.fire(
                    "user_joined_room", user=user, room_id=event.room_id
                )


    @log_function
    @defer.inlineCallbacks
    def backfill(self, dest, room_id, limit):
        events = yield self.hs.get_federation().backfill(dest, room_id, limit)

        for event in events:
            try:
                yield self.store.persist_event(event, backfilled=True)
            except:
                logger.exception("Failed to persist event: %s", event)

        defer.returnValue(events)

    @log_function
    @defer.inlineCallbacks
    def do_invite_join(self, target_host, room_id, joinee, content):
        federation = self.hs.get_federation()

        hosts = yield self.store.get_joined_hosts_for_room(room_id)
        if self.hs.hostname in hosts:
            # We are already in the room.
            logger.debug("We're already in the room apparently")
            defer.returnValue(False)

        # First get current state to see if we are already joined.
        try:
            yield federation.get_state_for_room(target_host, room_id)

            hosts = yield self.store.get_joined_hosts_for_room(room_id)
            if self.hs.hostname in hosts:
                # Oh, we were actually in the room already.
                logger.debug("We're already in the room apparently")
                defer.returnValue(False)
        except Exception:
            logger.exception("Failed to get current state")

        new_event = self.event_factory.create_event(
            etype=InviteJoinEvent.TYPE,
            target_host=target_host,
            room_id=room_id,
            user_id=joinee,
            content=content
        )

        new_event.destinations = [target_host]

        yield federation.handle_new_event(new_event)

        # TODO (erikj): Time out here.
        d = defer.Deferred()
        self.waiting_for_join_list.setdefault((joinee, room_id), []).append(d)
        yield d

        try:
            yield self.store.store_room(
                room_id,
                "",
                is_public=False
            )
        except:
            pass


        defer.returnValue(True)


    @log_function
    def _on_user_joined(self, user, room_id):
        waiters = self.waiting_for_join_list.get((user.to_string(), room_id), [])
        while waiters:
            waiters.pop().callback(None)
