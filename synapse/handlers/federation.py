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

from synapse.events.snapshot import EventContext
from synapse.events.utils import prune_event
from synapse.api.errors import (
    AuthError, FederationError, SynapseError, StoreError,
)
from synapse.api.events.room import RoomMemberEvent, RoomCreateEvent
from synapse.api.constants import Membership
from synapse.util.logutils import log_function
from synapse.util.async import run_on_reactor
from synapse.crypto.event_signing import (
    compute_event_signature, check_event_content_hash,
    add_hashes_and_signatures,
)
from syutil.jsonutil import encode_canonical_json

from twisted.internet import defer

import logging


logger = logging.getLogger(__name__)


class FederationHandler(BaseHandler):
    """Handles events that originated from federation.
        Responsible for:
        a) handling received Pdus before handing them on as Events to the rest
        of the home server (including auth and state conflict resoultion)
        b) converting events that were produced by local clients that may need
        to be sent to remote home servers.
        c) doing the necessary dances to invite remote users and join remote
        rooms.
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
        self.keyring = hs.get_keyring()

        self.lock_manager = hs.get_room_lock_manager()

        self.replication_layer.set_handler(self)

        # When joining a room we need to queue any events for that room up
        self.room_queues = {}

    @log_function
    @defer.inlineCallbacks
    def handle_new_event(self, event, snapshot, destinations):
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

        yield self.replication_layer.send_pdu(event, destinations)

    @log_function
    @defer.inlineCallbacks
    def on_receive_pdu(self, origin, pdu, backfilled, state=None):
        """ Called by the ReplicationLayer when we have a new pdu. We need to
        do auth checks and put it through the StateHandler.
        """
        event = pdu

        logger.debug("Got event: %s", event.event_id)

        # If we are currently in the process of joining this room, then we
        # queue up events for later processing.
        if event.room_id in self.room_queues:
            self.room_queues[event.room_id].append((pdu, origin))
            return

        logger.debug("Processing event: %s", event.event_id)

        redacted_event = prune_event(event)

        redacted_pdu_json = redacted_event.get_pdu_json()
        try:
            yield self.keyring.verify_json_for_server(
                event.origin, redacted_pdu_json
            )
        except SynapseError as e:
            logger.warn(
                "Signature check failed for %s redacted to %s",
                encode_canonical_json(pdu.get_pdu_json()),
                encode_canonical_json(redacted_pdu_json),
            )
            raise FederationError(
                "ERROR",
                e.code,
                e.msg,
                affected=event.event_id,
            )

        if not check_event_content_hash(event):
            logger.warn(
                "Event content has been tampered, redacting %s, %s",
                event.event_id, encode_canonical_json(event.get_full_dict())
            )
            event = redacted_event

        logger.debug("Event: %s", event)

        # FIXME (erikj): Awful hack to make the case where we are not currently
        # in the room work
        current_state = None
        is_in_room = yield self.auth.check_host_in_room(
            event.room_id,
            self.server_name
        )
        if not is_in_room and not event.internal_metadata.outlier:
            logger.debug("Got event for room we're not in.")

            replication_layer = self.replication_layer
            auth_chain = yield replication_layer.get_event_auth(
                origin,
                context=event.room_id,
                event_id=event.event_id,
            )

            for e in auth_chain:
                e.internal_metadata.outlier = True
                try:
                    yield self._handle_new_event(e, fetch_missing=False)
                except:
                    logger.exception(
                        "Failed to parse auth event %s",
                        e.event_id,
                    )

            if not state:
                state = yield replication_layer.get_state_for_context(
                    origin,
                    context=event.room_id,
                    event_id=event.event_id,
                )

            current_state = state

        if state:
            for e in state:
                e.internal_metadata.outlier = True
                try:
                    yield self._handle_new_event(e)
                except:
                    logger.exception(
                        "Failed to parse state event %s",
                        e.event_id,
                    )

        try:
            yield self._handle_new_event(
                event,
                state=state,
                backfilled=backfilled,
                current_state=current_state,
            )
        except AuthError as e:
            raise FederationError(
                "ERROR",
                e.code,
                e.msg,
                affected=event.event_id,
            )

        room = yield self.store.get_room(event.room_id)

        if not room:
            try:
                yield self.store.store_room(
                    room_id=event.room_id,
                    room_creator_user_id="",
                    is_public=False,
                )
            except StoreError:
                logger.exception("Failed to store room.")

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
                yield self.distributor.fire(
                    "user_joined_room", user=user, room_id=event.room_id
                )

    @log_function
    @defer.inlineCallbacks
    def backfill(self, dest, room_id, limit):
        """ Trigger a backfill request to `dest` for the given `room_id`
        """
        extremities = yield self.store.get_oldest_events_in_room(room_id)

        pdus = yield self.replication_layer.backfill(
            dest,
            room_id,
            limit,
            extremities=extremities,
        )

        events = []

        for pdu in pdus:
            event = pdu

            # FIXME (erikj): Not sure this actually works :/
            context = EventContext()
            yield self.state_handler.annotate_context_with_state(event, context)

            events.append(
                (event, context)
            )

            yield self.store.persist_event(
                event,
                context=context,
                backfilled=True
            )

        defer.returnValue(events)

    @defer.inlineCallbacks
    def send_invite(self, target_host, event):
        """ Sends the invite to the remote server for signing.

        Invites must be signed by the invitee's server before distribution.
        """
        pdu = yield self.replication_layer.send_invite(
            destination=target_host,
            context=event.room_id,
            event_id=event.event_id,
            pdu=event
        )

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    def on_event_auth(self, event_id):
        auth = yield self.store.get_auth_chain(event_id)

        for event in auth:
            event.signatures.update(
                compute_event_signature(
                    event,
                    self.hs.hostname,
                    self.hs.config.signing_key[0]
                )
            )

        defer.returnValue([e for e in auth])

    @log_function
    @defer.inlineCallbacks
    def do_invite_join(self, target_host, room_id, joinee, content, snapshot):
        """ Attempts to join the `joinee` to the room `room_id` via the
        server `target_host`.

        This first triggers a /make_join/ request that returns a partial
        event that we can fill out and sign. This is then sent to the
        remote server via /send_join/ which responds with the state at that
        event and the auth_chains.

        We suspend processing of any received events from this room until we
        have finished processing the join.
        """
        logger.debug("Joining %s to %s", joinee, room_id)

        pdu = yield self.replication_layer.make_join(
            target_host,
            room_id,
            joinee
        )

        logger.debug("Got response to make_join: %s", pdu)

        event = pdu

        # We should assert some things.
        assert(event.type == RoomMemberEvent.TYPE)
        assert(event.user_id == joinee)
        assert(event.state_key == joinee)
        assert(event.room_id == room_id)

        event.internal_metadata.outlier = False

        self.room_queues[room_id] = []

        builder = self.event_builder_factory.new(
            event.get_pdu_json()
        )

        try:
            builder.event_id = self.event_factory.create_event_id()
            builder.origin = self.hs.hostname
            builder.content = content

            if not hasattr(event, "signatures"):
                builder.signatures = {}

            add_hashes_and_signatures(
                builder,
                self.hs.hostname,
                self.hs.config.signing_key[0],
            )

            new_event = builder.build()

            ret = yield self.replication_layer.send_join(
                target_host,
                new_event
            )

            state = ret["state"]
            auth_chain = ret["auth_chain"]
            auth_chain.sort(key=lambda e: e.depth)

            logger.debug("do_invite_join auth_chain: %s", auth_chain)
            logger.debug("do_invite_join state: %s", state)

            logger.debug("do_invite_join event: %s", new_event)

            try:
                yield self.store.store_room(
                    room_id=room_id,
                    room_creator_user_id="",
                    is_public=False
                )
            except:
                # FIXME
                pass

            for e in auth_chain:
                e.internal_metadata.outlier = True
                try:
                    yield self._handle_new_event(e, fetch_missing=False)
                except:
                    logger.exception(
                        "Failed to parse auth event %s",
                        e.event_id,
                    )

            for e in state:
                # FIXME: Auth these.
                e.internal_metadata.outlier = True
                try:
                    yield self._handle_new_event(
                        e,
                        fetch_missing=True
                    )
                except:
                    logger.exception(
                        "Failed to parse state event %s",
                        e.event_id,
                    )

            yield self._handle_new_event(
                new_event,
                state=state,
                current_state=state,
            )

            yield self.notifier.on_new_room_event(
                new_event, extra_users=[joinee]
            )

            logger.debug("Finished joining %s to %s", joinee, room_id)
        finally:
            room_queue = self.room_queues[room_id]
            del self.room_queues[room_id]

            for p, origin in room_queue:
                try:
                    self.on_receive_pdu(origin, p, backfilled=False)
                except:
                    logger.exception("Couldn't handle pdu")

        defer.returnValue(True)

    @defer.inlineCallbacks
    @log_function
    def on_make_join_request(self, room_id, user_id):
        """ We've received a /make_join/ request, so we create a partial
        join event for the room and return that. We don *not* persist or
        process it until the other server has signed it and sent it back.
        """
        builder = self.event_builder_factory.new({
            "type": RoomMemberEvent.TYPE,
            "content": {"membership": Membership.JOIN},
            "room_id": room_id,
            "sender": user_id,
            "state_key": user_id,
        })

        event, context = yield self._create_new_client_event(
            builder=builder,
        )

        self.auth.check(event, auth_events=context.auth_events)

        pdu = event

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    @log_function
    def on_send_join_request(self, origin, pdu):
        """ We have received a join event for a room. Fully process it and
        respond with the current state and auth chains.
        """
        event = pdu

        logger.debug(
            "on_send_join_request: Got event: %s, signatures: %s",
            event.event_id,
            event.signatures,
        )

        event.internal_metadata.outlier = False

        context = yield self._handle_new_event(event)

        logger.debug(
            "on_send_join_request: After _handle_new_event: %s, sigs: %s",
            event.event_id,
            event.signatures,
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
            if event.content["membership"] == Membership.JOIN:
                user = self.hs.parse_userid(event.state_key)
                yield self.distributor.fire(
                    "user_joined_room", user=user, room_id=event.room_id
                )

        new_pdu = event

        destinations = set()

        for k, s in context.current_state.items():
            try:
                if k[0] == RoomMemberEvent.TYPE:
                    if s.content["membership"] == Membership.JOIN:
                        destinations.add(
                            self.hs.parse_userid(s.state_key).domain
                        )
            except:
                logger.warn(
                    "Failed to get destination from event %s", s.event_id
                )

        logger.debug(
            "on_send_join_request: Sending event: %s, signatures: %s",
            event.event_id,
            event.signatures,
        )

        yield self.replication_layer.send_pdu(new_pdu, destinations)

        auth_chain = yield self.store.get_auth_chain(event.event_id)

        defer.returnValue({
            "state": context.current_state.values(),
            "auth_chain": auth_chain,
        })

    @defer.inlineCallbacks
    def on_invite_request(self, origin, pdu):
        """ We've got an invite event. Process and persist it. Sign it.

        Respond with the now signed event.
        """
        event = pdu

        context = EventContext()

        event.internal_metadata.outlier = True

        event.signatures.update(
            compute_event_signature(
                event,
                self.hs.hostname,
                self.hs.config.signing_key[0]
            )
        )

        yield self.state_handler.annotate_context_with_state(event, context)

        yield self.store.persist_event(
            event,
            context=context,
            backfilled=False,
        )

        target_user = self.hs.parse_userid(event.state_key)
        yield self.notifier.on_new_room_event(
            event, extra_users=[target_user],
        )

        defer.returnValue(event)

    @defer.inlineCallbacks
    def get_state_for_pdu(self, origin, room_id, event_id):
        yield run_on_reactor()

        in_room = yield self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        state_groups = yield self.store.get_state_groups(
            [event_id]
        )

        if state_groups:
            _, state = state_groups.items().pop()
            results = {
                (e.type, e.state_key): e for e in state
            }

            event = yield self.store.get_event(event_id)
            if hasattr(event, "state_key"):
                # Get previous state
                if hasattr(event, "replaces_state") and event.replaces_state:
                    prev_event = yield self.store.get_event(
                        event.replaces_state
                    )
                    results[(event.type, event.state_key)] = prev_event
                else:
                    del results[(event.type, event.state_key)]

            res = results.values()
            for event in res:
                event.signatures.update(
                    compute_event_signature(
                        event,
                        self.hs.hostname,
                        self.hs.config.signing_key[0]
                    )
                )

            defer.returnValue(res)
        else:
            defer.returnValue([])

    @defer.inlineCallbacks
    @log_function
    def on_backfill_request(self, origin, context, pdu_list, limit):
        in_room = yield self.auth.check_host_in_room(context, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        events = yield self.store.get_backfill_events(
            context,
            pdu_list,
            limit
        )

        defer.returnValue(events)

    @defer.inlineCallbacks
    @log_function
    def get_persisted_pdu(self, origin, event_id, do_auth=True):
        """ Get a PDU from the database with given origin and id.

        Returns:
            Deferred: Results in a `Pdu`.
        """
        event = yield self.store.get_event(
            event_id,
            allow_none=True,
        )

        if event:
            # FIXME: This is a temporary work around where we occasionally
            # return events slightly differently than when they were
            # originally signed
            event.signatures.update(
                compute_event_signature(
                    event,
                    self.hs.hostname,
                    self.hs.config.signing_key[0]
                )
            )

            if do_auth:
                in_room = yield self.auth.check_host_in_room(
                    event.room_id,
                    origin
                )
                if not in_room:
                    raise AuthError(403, "Host not in room.")

            defer.returnValue(event)
        else:
            defer.returnValue(None)

    @log_function
    def get_min_depth_for_context(self, context):
        return self.store.get_min_depth(context)

    @log_function
    def _on_user_joined(self, user, room_id):
        waiters = self.waiting_for_join_list.get(
            (user.to_string(), room_id),
            []
        )
        while waiters:
            waiters.pop().callback(None)

    @defer.inlineCallbacks
    def _handle_new_event(self, event, state=None, backfilled=False,
                          current_state=None, fetch_missing=True):
        context = EventContext()

        logger.debug(
            "_handle_new_event: Before annotate: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        yield self.state_handler.annotate_context_with_state(
            event,
            context,
            old_state=state
        )

        logger.debug(
            "_handle_new_event: Before auth fetch: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        is_new_state = not event.internal_metadata.outlier

        known_ids = set(
            [s.event_id for s in context.auth_events.values()]
        )
        for e_id, _ in event.auth_events:
            if e_id not in known_ids:
                e = yield self.store.get_event(
                    e_id, allow_none=True,
                )

                if not e:
                    # TODO: Do some conflict res to make sure that we're
                    # not the ones who are wrong.
                    logger.info(
                        "Rejecting %s as %s not in db or %s",
                        event.event_id, e_id, known_ids,
                    )
                    raise AuthError(403, "Auth events are stale")

                context.auth_events[(e.type, e.state_key)] = e

        logger.debug(
            "_handle_new_event: Before hack: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        if event.type == RoomMemberEvent.TYPE and not event.auth_events:
            if len(event.prev_events) == 1:
                c = yield self.store.get_event(event.prev_events[0][0])
                if c.type == RoomCreateEvent.TYPE:
                    context.auth_events[(c.type, c.state_key)] = c

        logger.debug(
            "_handle_new_event: Before auth check: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        self.auth.check(event, auth_events=context.auth_events)

        logger.debug(
            "_handle_new_event: Before persist_event: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        yield self.store.persist_event(
            event,
            context=context,
            backfilled=backfilled,
            is_new_state=(is_new_state and not backfilled),
            current_state=current_state,
        )

        logger.debug(
            "_handle_new_event: After persist_event: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        defer.returnValue(context)
