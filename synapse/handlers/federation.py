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
from synapse.federation.pdu_codec import PduCodec
from synapse.api.errors import SynapseError

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

        pdu = self.pdu_codec.pdu_from_event(event)

        if not hasattr(pdu, "destinations") or not pdu.destinations:
            pdu.destinations = []

        yield self.replication_layer.send_pdu(pdu)

    @log_function
    @defer.inlineCallbacks
    def on_receive_pdu(self, pdu, backfilled):
        """ Called by the ReplicationLayer when we have a new pdu. We need to
        do auth checks and put it throught the StateHandler.
        """
        event = self.pdu_codec.event_from_pdu(pdu)

        logger.debug("Got event: %s", event.event_id)

        with (yield self.lock_manager.lock(pdu.context)):
            if event.is_state and not backfilled:
                is_new_state = yield self.state_handler.handle_new_state(
                    pdu
                )
            else:
                is_new_state = False
        # TODO: Implement something in federation that allows us to
        # respond to PDU.

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
                do_auth=False,
            )

        else:
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
                        event.origin, event.room_id
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

        # First get current state to see if we are already joined.
        try:
            yield self.replication_layer.get_state_for_context(
                target_host, room_id
            )

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

        snapshot.fill_out_prev_events(new_event)
        yield self.handle_new_event(new_event, snapshot)

        # TODO (erikj): Time out here.
        d = defer.Deferred()
        self.waiting_for_join_list.setdefault((joinee, room_id), []).append(d)
        reactor.callLater(10, d.cancel)

        try:
            yield d
        except defer.CancelledError:
            raise SynapseError(500, "Unable to join remote room")

        try:
            yield self.store.store_room(
                room_id=room_id,
                room_creator_user_id="",
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
