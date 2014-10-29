# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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
from synapse.federation.pdu_codec import PduCodec, encode_event_id
from synapse.api.errors import SynapseError
from synapse.util.async import run_on_reactor

from twisted.internet import defer, reactor

import logging


logger = logging.getLogger(__name__)


class FederationHandler(BaseHandler):
    """Handles events that originated from federation.
        Responsible for:
        a) handling received Pdus before handing them on as Events to the rest
        of the home server (including auth and state conflict resoultion)
        b) converting events that were produced by local clients that may need
        to be sent to remote home servers.
    """

    def __init__(self, hs):
        super(FederationHandler, self).__init__(hs)

        self.distributor.observe(
            "user_joined_room",
            self._on_user_joined
        )

        self.waiting_for_join_list = {}

        self.store = hs.get_datastore()
        self.replication_layer = hs.get_replication_layer()
        self.state_handler = hs.get_state_handler()
        # self.auth_handler = gs.get_auth_handler()
        self.server_name = hs.hostname

        self.lock_manager = hs.get_room_lock_manager()

        self.replication_layer.set_handler(self)

        self.pdu_codec = PduCodec(hs)

        # When joining a room we need to queue any events for that room up
        self.room_queues = {}

    @log_function
    @defer.inlineCallbacks
    def handle_new_event(self, event, snapshot):
        """ Takes in an event from the client to server side, that has already
        been authed and handled by the state module, and sends it to any
        remote home servers that may be interested.

        Args:
            event
            snapshot (.storage.Snapshot): THe snapshot the event happened after

        Returns:
            Deferred: Resolved when it has successfully been queued for
            processing.
        """

        yield run_on_reactor()

        pdu = self.pdu_codec.pdu_from_event(event)

        if not hasattr(pdu, "destinations") or not pdu.destinations:
            pdu.destinations = []

        yield self.replication_layer.send_pdu(pdu)

    @log_function
    @defer.inlineCallbacks
    def on_receive_pdu(self, pdu, backfilled, state=None):
        """ Called by the ReplicationLayer when we have a new pdu. We need to
        do auth checks and put it through the StateHandler.
        """
        event = self.pdu_codec.event_from_pdu(pdu)

        logger.debug("Got event: %s", event.event_id)

        if event.room_id in self.room_queues:
            self.room_queues[event.room_id].append(pdu)
            return

        logger.debug("Processing event: %s", event.event_id)

        if state:
            state = [self.pdu_codec.event_from_pdu(p) for p in state]

        is_new_state = yield self.state_handler.annotate_state_groups(
            event,
            state=state
        )

        logger.debug("Event: %s", event)

        if not backfilled:
            yield self.auth.check(event, None, raises=True)

        is_new_state = is_new_state and not backfilled

        # TODO: Implement something in federation that allows us to
        # respond to PDU.

        with (yield self.room_lock.lock(event.room_id)):
            yield self.store.persist_event(
                event,
                backfilled,
                is_new_state=is_new_state
            )

        room = yield self.store.get_room(event.room_id)

        if not room:
            # Huh, let's try and get the current state
            try:
                yield self.replication_layer.get_state_for_context(
                    event.origin, event.room_id, pdu.pdu_id, pdu.origin,
                )

                hosts = yield self.store.get_joined_hosts_for_room(
                    event.room_id
                )
                if self.hs.hostname in hosts:
                    try:
                        yield self.store.store_room(
                            room_id=event.room_id,
                            room_creator_user_id="",
                            is_public=False,
                        )
                    except:
                        pass
            except:
                logger.exception(
                    "Failed to get current state for room %s",
                    event.room_id
                )

        if not backfilled:
            extra_users = []
            if event.type == RoomMemberEvent.TYPE:
                target_user_id = event.state_key
                target_user = self.hs.parse_userid(target_user_id)
                extra_users.append(target_user)

            yield self.notifier.on_new_room_event(
                event, extra_users=extra_users
            )

        if event.type == RoomMemberEvent.TYPE:
            if event.membership == Membership.JOIN:
                user = self.hs.parse_userid(event.state_key)
                self.distributor.fire(
                    "user_joined_room", user=user, room_id=event.room_id
                )

    @log_function
    @defer.inlineCallbacks
    def backfill(self, dest, room_id, limit):
        pdus = yield self.replication_layer.backfill(dest, room_id, limit)

        events = []

        for pdu in pdus:
            event = self.pdu_codec.event_from_pdu(pdu)

            # FIXME (erikj): Not sure this actually works :/
            yield self.state_handler.annotate_state_groups(event)

            events.append(event)

            yield self.store.persist_event(event, backfilled=True)

        defer.returnValue(events)

    @log_function
    @defer.inlineCallbacks
    def do_invite_join(self, target_host, room_id, joinee, content, snapshot):
        hosts = yield self.store.get_joined_hosts_for_room(room_id)
        if self.hs.hostname in hosts:
            # We are already in the room.
            logger.debug("We're already in the room apparently")
            defer.returnValue(False)

        pdu = yield self.replication_layer.make_join(
            target_host,
            room_id,
            joinee
        )

        logger.debug("Got response to make_join: %s", pdu)

        event = self.pdu_codec.event_from_pdu(pdu)

        # We should assert some things.
        assert(event.type == RoomMemberEvent.TYPE)
        assert(event.user_id == joinee)
        assert(event.state_key == joinee)
        assert(event.room_id == room_id)

        event.outlier = False

        self.room_queues[room_id] = []

        try:
            event.event_id = self.event_factory.create_event_id()
            event.content = content

            state = yield self.replication_layer.send_join(
                target_host,
                self.pdu_codec.pdu_from_event(event)
            )

            state = [self.pdu_codec.event_from_pdu(p) for p in state]

            logger.debug("do_invite_join state: %s", state)

            is_new_state = yield self.state_handler.annotate_state_groups(
                event,
                state=state
            )

            logger.debug("do_invite_join event: %s", event)

            try:
                yield self.store.store_room(
                    room_id=room_id,
                    room_creator_user_id="",
                    is_public=False
                )
            except:
                # FIXME
                pass

            for e in state:
                # FIXME: Auth these.
                e.outlier = True

                yield self.state_handler.annotate_state_groups(
                    e,
                )

                yield self.store.persist_event(
                    e,
                    backfilled=False,
                    is_new_state=False
                )

            yield self.store.persist_event(
                event,
                backfilled=False,
                is_new_state=is_new_state
            )
        finally:
            room_queue = self.room_queues[room_id]
            del self.room_queues[room_id]

            for p in room_queue:
                yield self.on_receive_pdu(p, backfilled=False)

        defer.returnValue(True)

    @defer.inlineCallbacks
    @log_function
    def on_make_join_request(self, context, user_id):
        event = self.event_factory.create_event(
            etype=RoomMemberEvent.TYPE,
            content={"membership": Membership.JOIN},
            room_id=context,
            user_id=user_id,
            state_key=user_id,
        )

        snapshot = yield self.store.snapshot_room(
            event.room_id, event.user_id,
        )
        snapshot.fill_out_prev_events(event)

        yield self.state_handler.annotate_state_groups(event)
        yield self.auth.check(event, None, raises=True)

        pdu = self.pdu_codec.pdu_from_event(event)

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    @log_function
    def on_send_join_request(self, origin, pdu):
        event = self.pdu_codec.event_from_pdu(pdu)

        event.outlier = False

        is_new_state = yield self.state_handler.annotate_state_groups(event)
        yield self.auth.check(event, None, raises=True)

        # FIXME (erikj):  All this is duplicated above :(

        yield self.store.persist_event(
            event,
            backfilled=False,
            is_new_state=is_new_state
        )

        extra_users = []
        if event.type == RoomMemberEvent.TYPE:
            target_user_id = event.state_key
            target_user = self.hs.parse_userid(target_user_id)
            extra_users.append(target_user)

        yield self.notifier.on_new_room_event(
            event, extra_users=extra_users
        )

        if event.type == RoomMemberEvent.TYPE:
            if event.membership == Membership.JOIN:
                user = self.hs.parse_userid(event.state_key)
                self.distributor.fire(
                    "user_joined_room", user=user, room_id=event.room_id
                )

        new_pdu = self.pdu_codec.pdu_from_event(event);
        new_pdu.destinations = yield self.store.get_joined_hosts_for_room(
            event.room_id
        )

        yield self.replication_layer.send_pdu(new_pdu)

        defer.returnValue([
            self.pdu_codec.pdu_from_event(e)
            for e in event.state_events.values()
        ])

    @defer.inlineCallbacks
    def get_state_for_pdu(self, pdu_id, pdu_origin):
        state_groups = yield self.store.get_state_groups(
            [encode_event_id(pdu_id, pdu_origin)]
        )

        if state_groups:
            defer.returnValue(
                [
                    self.pdu_codec.pdu_from_event(s)
                    for s in state_groups[0].state
                ]
            )
        else:
            defer.returnValue([])

    @log_function
    def _on_user_joined(self, user, room_id):
        waiters = self.waiting_for_join_list.get((user.to_string(), room_id), [])
        while waiters:
            waiters.pop().callback(None)
