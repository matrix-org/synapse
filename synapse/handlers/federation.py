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

"""Contains handlers for federation events."""

from ._base import BaseHandler

from synapse.api.errors import (
    AuthError, FederationError, StoreError,
)
from synapse.api.constants import EventTypes, Membership, RejectedReason
from synapse.util.logutils import log_function
from synapse.util.async import run_on_reactor
from synapse.util.frozenutils import unfreeze
from synapse.crypto.event_signing import (
    compute_event_signature, add_hashes_and_signatures,
)
from synapse.types import UserID

from twisted.internet import defer

import itertools
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
    def handle_new_event(self, event, destinations):
        """ Takes in an event from the client to server side, that has already
        been authed and handled by the state module, and sends it to any
        remote home servers that may be interested.

        Args:
            event: The event to send
            destinations: A list of destinations to send it to

        Returns:
            Deferred: Resolved when it has successfully been queued for
            processing.
        """

        yield run_on_reactor()

        self.replication_layer.send_pdu(event, destinations)

    @log_function
    @defer.inlineCallbacks
    def on_receive_pdu(self, origin, pdu, backfilled, state=None,
                       auth_chain=None):
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

        logger.debug("Event: %s", event)

        # FIXME (erikj): Awful hack to make the case where we are not currently
        # in the room work
        current_state = None
        is_in_room = yield self.auth.check_host_in_room(
            event.room_id,
            self.server_name
        )
        if not is_in_room and not event.internal_metadata.is_outlier():
            logger.debug("Got event for room we're not in.")
            current_state = state

        event_ids = set()
        if state:
            event_ids |= {e.event_id for e in state}
        if auth_chain:
            event_ids |= {e.event_id for e in auth_chain}

        seen_ids = set(
            (yield self.store.have_events(event_ids)).keys()
        )

        if state and auth_chain is not None:
            # If we have any state or auth_chain given to us by the replication
            # layer, then we should handle them (if we haven't before.)
            for e in itertools.chain(auth_chain, state):
                if e.event_id in seen_ids:
                    continue

                e.internal_metadata.outlier = True
                try:
                    auth_ids = [e_id for e_id, _ in e.auth_events]
                    auth = {
                        (e.type, e.state_key): e for e in auth_chain
                        if e.event_id in auth_ids
                    }
                    yield self._handle_new_event(
                        origin, e, auth_events=auth
                    )
                    seen_ids.add(e.event_id)
                except:
                    logger.exception(
                        "Failed to handle state event %s",
                        e.event_id,
                    )

        try:
            yield self._handle_new_event(
                origin,
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

        # if we're receiving valid events from an origin,
        # it's probably a good idea to mark it as not in retry-state
        # for sending (although this is a bit of a leap)
        retry_timings = yield self.store.get_destination_retry_timings(origin)
        if (retry_timings and retry_timings.retry_last_ts):
            self.store.set_destination_retry_timings(origin, 0, 0)

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
            if event.type == EventTypes.Member:
                target_user_id = event.state_key
                target_user = UserID.from_string(target_user_id)
                extra_users.append(target_user)

            yield self.notifier.on_new_room_event(
                event, extra_users=extra_users
            )

        if event.type == EventTypes.Member:
            if event.membership == Membership.JOIN:
                user = UserID.from_string(event.state_key)
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
            context = yield self.state_handler.compute_event_context(event)

            events.append((event, context))

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
            room_id=event.room_id,
            event_id=event.event_id,
            pdu=event
        )

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    def on_event_auth(self, event_id):
        auth = yield self.store.get_auth_chain([event_id])

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
    def do_invite_join(self, target_hosts, room_id, joinee, content, snapshot):
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

        origin, pdu = yield self.replication_layer.make_join(
            target_hosts,
            room_id,
            joinee
        )

        logger.debug("Got response to make_join: %s", pdu)

        event = pdu

        # We should assert some things.
        # FIXME: Do this in a nicer way
        assert(event.type == EventTypes.Member)
        assert(event.user_id == joinee)
        assert(event.state_key == joinee)
        assert(event.room_id == room_id)

        event.internal_metadata.outlier = False

        self.room_queues[room_id] = []

        builder = self.event_builder_factory.new(
            unfreeze(event.get_pdu_json())
        )

        handled_events = set()

        try:
            builder.event_id = self.event_builder_factory.create_event_id()
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

            # Try the host we successfully got a response to /make_join/
            # request first.
            try:
                target_hosts.remove(origin)
                target_hosts.insert(0, origin)
            except ValueError:
                pass

            ret = yield self.replication_layer.send_join(
                target_hosts,
                new_event
            )

            origin = ret["origin"]
            state = ret["state"]
            auth_chain = ret["auth_chain"]
            auth_chain.sort(key=lambda e: e.depth)

            handled_events.update([s.event_id for s in state])
            handled_events.update([a.event_id for a in auth_chain])
            handled_events.add(new_event.event_id)

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

                if e.event_id == event.event_id:
                    continue

                try:
                    auth_ids = [e_id for e_id, _ in e.auth_events]
                    auth = {
                        (e.type, e.state_key): e for e in auth_chain
                        if e.event_id in auth_ids
                    }
                    yield self._handle_new_event(
                        origin, e, auth_events=auth
                    )
                except:
                    logger.exception(
                        "Failed to handle auth event %s",
                        e.event_id,
                    )

            for e in state:
                if e.event_id == event.event_id:
                    continue

                e.internal_metadata.outlier = True
                try:
                    auth_ids = [e_id for e_id, _ in e.auth_events]
                    auth = {
                        (e.type, e.state_key): e for e in auth_chain
                        if e.event_id in auth_ids
                    }
                    yield self._handle_new_event(
                        origin, e, auth_events=auth
                    )
                except:
                    logger.exception(
                        "Failed to handle state event %s",
                        e.event_id,
                    )

            auth_ids = [e_id for e_id, _ in event.auth_events]
            auth_events = {
                (e.type, e.state_key): e for e in auth_chain
                if e.event_id in auth_ids
            }

            yield self._handle_new_event(
                origin,
                new_event,
                state=state,
                current_state=state,
                auth_events=auth_events,
            )

            yield self.notifier.on_new_room_event(
                new_event, extra_users=[joinee]
            )

            logger.debug("Finished joining %s to %s", joinee, room_id)
        finally:
            room_queue = self.room_queues[room_id]
            del self.room_queues[room_id]

            for p, origin in room_queue:
                if p.event_id in handled_events:
                    continue

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
            "type": EventTypes.Member,
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

        context = yield self._handle_new_event(origin, event)

        logger.debug(
            "on_send_join_request: After _handle_new_event: %s, sigs: %s",
            event.event_id,
            event.signatures,
        )

        extra_users = []
        if event.type == EventTypes.Member:
            target_user_id = event.state_key
            target_user = UserID.from_string(target_user_id)
            extra_users.append(target_user)

        yield self.notifier.on_new_room_event(
            event, extra_users=extra_users
        )

        if event.type == EventTypes.Member:
            if event.content["membership"] == Membership.JOIN:
                user = UserID.from_string(event.state_key)
                yield self.distributor.fire(
                    "user_joined_room", user=user, room_id=event.room_id
                )

        new_pdu = event

        destinations = set()

        for k, s in context.current_state.items():
            try:
                if k[0] == EventTypes.Member:
                    if s.content["membership"] == Membership.JOIN:
                        destinations.add(
                            UserID.from_string(s.state_key).domain
                        )
            except:
                logger.warn(
                    "Failed to get destination from event %s", s.event_id
                )

        destinations.discard(origin)

        logger.debug(
            "on_send_join_request: Sending event: %s, signatures: %s",
            event.event_id,
            event.signatures,
        )

        self.replication_layer.send_pdu(new_pdu, destinations)

        state_ids = [e.event_id for e in context.current_state.values()]
        auth_chain = yield self.store.get_auth_chain(set(
            [event.event_id] + state_ids
        ))

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

        event.internal_metadata.outlier = True

        event.signatures.update(
            compute_event_signature(
                event,
                self.hs.hostname,
                self.hs.config.signing_key[0]
            )
        )

        context = yield self.state_handler.compute_event_context(event)

        yield self.store.persist_event(
            event,
            context=context,
            backfilled=False,
        )

        target_user = UserID.from_string(event.state_key)
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
            if event and event.is_state():
                # Get previous state
                if "replaces_state" in event.unsigned:
                    prev_id = event.unsigned["replaces_state"]
                    if prev_id != event.event_id:
                        prev_event = yield self.store.get_event(prev_id)
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
    def on_backfill_request(self, origin, room_id, pdu_list, limit):
        in_room = yield self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        events = yield self.store.get_backfill_events(
            room_id,
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
            allow_rejected=True,
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
    @log_function
    def _handle_new_event(self, origin, event, state=None, backfilled=False,
                          current_state=None, auth_events=None):

        logger.debug(
            "_handle_new_event: %s, sigs: %s",
            event.event_id, event.signatures,
        )

        context = yield self.state_handler.compute_event_context(
            event, old_state=state
        )

        if not auth_events:
            auth_events = context.auth_events

        logger.debug(
            "_handle_new_event: %s, auth_events: %s",
            event.event_id, auth_events,
        )

        is_new_state = not event.internal_metadata.is_outlier()

        # This is a hack to fix some old rooms where the initial join event
        # didn't reference the create event in its auth events.
        if event.type == EventTypes.Member and not event.auth_events:
            if len(event.prev_events) == 1:
                c = yield self.store.get_event(event.prev_events[0][0])
                if c.type == EventTypes.Create:
                    auth_events[(c.type, c.state_key)] = c

        try:
            yield self.do_auth(
                origin, event, context, auth_events=auth_events
            )
        except AuthError as e:
            logger.warn(
                "Rejecting %s because %s",
                event.event_id, e.msg
            )

            context.rejected = RejectedReason.AUTH_ERROR

            # FIXME: Don't store as rejected with AUTH_ERROR if we haven't
            # seen all the auth events.
            yield self.store.persist_event(
                event,
                context=context,
                backfilled=backfilled,
                is_new_state=False,
                current_state=current_state,
            )
            raise

        yield self.store.persist_event(
            event,
            context=context,
            backfilled=backfilled,
            is_new_state=(is_new_state and not backfilled),
            current_state=current_state,
        )

        defer.returnValue(context)

    @defer.inlineCallbacks
    def on_query_auth(self, origin, event_id, remote_auth_chain, rejects,
                      missing):
        # Just go through and process each event in `remote_auth_chain`. We
        # don't want to fall into the trap of `missing` being wrong.
        for e in remote_auth_chain:
            try:
                yield self._handle_new_event(origin, e)
            except AuthError:
                pass

        # Now get the current auth_chain for the event.
        local_auth_chain = yield self.store.get_auth_chain([event_id])

        # TODO: Check if we would now reject event_id. If so we need to tell
        # everyone.

        ret = yield self.construct_auth_difference(
            local_auth_chain, remote_auth_chain
        )

        for event in ret["auth_chain"]:
            event.signatures.update(
                compute_event_signature(
                    event,
                    self.hs.hostname,
                    self.hs.config.signing_key[0]
                )
            )

        logger.debug("on_query_auth returning: %s", ret)

        defer.returnValue(ret)

    @defer.inlineCallbacks
    @log_function
    def do_auth(self, origin, event, context, auth_events):
        # Check if we have all the auth events.
        have_events = yield self.store.have_events(
            [e_id for e_id, _ in event.auth_events]
        )

        event_auth_events = set(e_id for e_id, _ in event.auth_events)
        seen_events = set(have_events.keys())

        missing_auth = event_auth_events - seen_events

        if missing_auth:
            logger.info("Missing auth: %s", missing_auth)
            # If we don't have all the auth events, we need to get them.
            try:
                remote_auth_chain = yield self.replication_layer.get_event_auth(
                    origin, event.room_id, event.event_id
                )

                seen_remotes = yield self.store.have_events(
                    [e.event_id for e in remote_auth_chain]
                )

                for e in remote_auth_chain:
                    if e.event_id in seen_remotes.keys():
                        continue

                    if e.event_id == event.event_id:
                        continue

                    try:
                        auth_ids = [e_id for e_id, _ in e.auth_events]
                        auth = {
                            (e.type, e.state_key): e for e in remote_auth_chain
                            if e.event_id in auth_ids
                        }
                        e.internal_metadata.outlier = True

                        logger.debug(
                            "do_auth %s missing_auth: %s",
                            event.event_id, e.event_id
                        )
                        yield self._handle_new_event(
                            origin, e, auth_events=auth
                        )

                        if e.event_id in event_auth_events:
                            auth_events[(e.type, e.state_key)] = e
                    except AuthError:
                        pass

                have_events = yield self.store.have_events(
                    [e_id for e_id, _ in event.auth_events]
                )
                seen_events = set(have_events.keys())
            except:
                # FIXME:
                logger.exception("Failed to get auth chain")

        # FIXME: Assumes we have and stored all the state for all the
        # prev_events
        current_state = set(e.event_id for e in auth_events.values())
        different_auth = event_auth_events - current_state

        if different_auth and not event.internal_metadata.is_outlier():
            # Do auth conflict res.
            logger.info("Different auth: %s", different_auth)

            different_events = yield defer.gatherResults(
                [
                    self.store.get_event(
                        d,
                        allow_none=True,
                        allow_rejected=False,
                    )
                    for d in different_auth
                    if d in have_events and not have_events[d]
                ],
                consumeErrors=True
            )

            if different_events:
                local_view = dict(auth_events)
                remote_view = dict(auth_events)
                remote_view.update({
                    (d.type, d.state_key): d for d in different_events
                })

                new_state, prev_state = self.state_handler.resolve_events(
                    [local_view.values(), remote_view.values()],
                    event
                )

                auth_events.update(new_state)

                current_state = set(e.event_id for e in auth_events.values())
                different_auth = event_auth_events - current_state

                context.current_state.update(auth_events)
                context.state_group = None

        if different_auth and not event.internal_metadata.is_outlier():
            logger.info("Different auth after resolution: %s", different_auth)

            # Only do auth resolution if we have something new to say.
            # We can't rove an auth failure.
            do_resolution = False

            provable = [
                RejectedReason.NOT_ANCESTOR, RejectedReason.NOT_ANCESTOR,
            ]

            for e_id in different_auth:
                if e_id in have_events:
                    if have_events[e_id] in provable:
                        do_resolution = True
                        break

            if do_resolution:
                # 1. Get what we think is the auth chain.
                auth_ids = self.auth.compute_auth_events(
                    event, context.current_state
                )
                local_auth_chain = yield self.store.get_auth_chain(auth_ids)

                try:
                    # 2. Get remote difference.
                    result = yield self.replication_layer.query_auth(
                        origin,
                        event.room_id,
                        event.event_id,
                        local_auth_chain,
                    )

                    seen_remotes = yield self.store.have_events(
                        [e.event_id for e in result["auth_chain"]]
                    )

                    # 3. Process any remote auth chain events we haven't seen.
                    for ev in result["auth_chain"]:
                        if ev.event_id in seen_remotes.keys():
                            continue

                        if ev.event_id == event.event_id:
                            continue

                        try:
                            auth_ids = [e_id for e_id, _ in ev.auth_events]
                            auth = {
                                (e.type, e.state_key): e
                                for e in result["auth_chain"]
                                if e.event_id in auth_ids
                            }
                            ev.internal_metadata.outlier = True

                            logger.debug(
                                "do_auth %s different_auth: %s",
                                event.event_id, e.event_id
                            )

                            yield self._handle_new_event(
                                origin, ev, auth_events=auth
                            )

                            if ev.event_id in event_auth_events:
                                auth_events[(ev.type, ev.state_key)] = ev
                        except AuthError:
                            pass

                except:
                    # FIXME:
                    logger.exception("Failed to query auth chain")

                # 4. Look at rejects and their proofs.
                # TODO.

                context.current_state.update(auth_events)
                context.state_group = None

        try:
            self.auth.check(event, auth_events=auth_events)
        except AuthError:
            raise

    @defer.inlineCallbacks
    def construct_auth_difference(self, local_auth, remote_auth):
        """ Given a local and remote auth chain, find the differences. This
        assumes that we have already processed all events in remote_auth

        Params:
            local_auth (list)
            remote_auth (list)

        Returns:
            dict
        """

        logger.debug("construct_auth_difference Start!")

        # TODO: Make sure we are OK with local_auth or remote_auth having more
        # auth events in them than strictly necessary.

        def sort_fun(ev):
            return ev.depth, ev.event_id

        logger.debug("construct_auth_difference after sort_fun!")

        # We find the differences by starting at the "bottom" of each list
        # and iterating up on both lists. The lists are ordered by depth and
        # then event_id, we iterate up both lists until we find the event ids
        # don't match. Then we look at depth/event_id to see which side is
        # missing that event, and iterate only up that list. Repeat.

        remote_list = list(remote_auth)
        remote_list.sort(key=sort_fun)

        local_list = list(local_auth)
        local_list.sort(key=sort_fun)

        local_iter = iter(local_list)
        remote_iter = iter(remote_list)

        logger.debug("construct_auth_difference before get_next!")

        def get_next(it, opt=None):
            try:
                return it.next()
            except:
                return opt

        current_local = get_next(local_iter)
        current_remote = get_next(remote_iter)

        logger.debug("construct_auth_difference before while")

        missing_remotes = []
        missing_locals = []
        while current_local or current_remote:
            if current_remote is None:
                missing_locals.append(current_local)
                current_local = get_next(local_iter)
                continue

            if current_local is None:
                missing_remotes.append(current_remote)
                current_remote = get_next(remote_iter)
                continue

            if current_local.event_id == current_remote.event_id:
                current_local = get_next(local_iter)
                current_remote = get_next(remote_iter)
                continue

            if current_local.depth < current_remote.depth:
                missing_locals.append(current_local)
                current_local = get_next(local_iter)
                continue

            if current_local.depth > current_remote.depth:
                missing_remotes.append(current_remote)
                current_remote = get_next(remote_iter)
                continue

            # They have the same depth, so we fall back to the event_id order
            if current_local.event_id < current_remote.event_id:
                missing_locals.append(current_local)
                current_local = get_next(local_iter)

            if current_local.event_id > current_remote.event_id:
                missing_remotes.append(current_remote)
                current_remote = get_next(remote_iter)
                continue

        logger.debug("construct_auth_difference after while")

        # missing locals should be sent to the server
        # We should find why we are missing remotes, as they will have been
        # rejected.

        # Remove events from missing_remotes if they are referencing a missing
        # remote. We only care about the "root" rejected ones.
        missing_remote_ids = [e.event_id for e in missing_remotes]
        base_remote_rejected = list(missing_remotes)
        for e in missing_remotes:
            for e_id, _ in e.auth_events:
                if e_id in missing_remote_ids:
                    try:
                        base_remote_rejected.remove(e)
                    except ValueError:
                        pass

        reason_map = {}

        for e in base_remote_rejected:
            reason = yield self.store.get_rejection_reason(e.event_id)
            if reason is None:
                # TODO: e is not in the current state, so we should
                # construct some proof of that.
                continue

            reason_map[e.event_id] = reason

            if reason == RejectedReason.AUTH_ERROR:
                pass
            elif reason == RejectedReason.REPLACED:
                # TODO: Get proof
                pass
            elif reason == RejectedReason.NOT_ANCESTOR:
                # TODO: Get proof.
                pass

        logger.debug("construct_auth_difference returning")

        defer.returnValue({
            "auth_chain": local_auth,
            "rejects": {
                e.event_id: {
                    "reason": reason_map[e.event_id],
                    "proof": None,
                }
                for e in base_remote_rejected
            },
            "missing": [e.event_id for e in missing_locals],
        })
