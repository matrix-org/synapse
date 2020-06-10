# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import itertools
import logging
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import six
from six import iteritems, itervalues
from six.moves import http_client, zip

import attr
from signedjson.key import decode_verify_key_bytes
from signedjson.sign import verify_signed_json
from unpaddedbase64 import decode_base64

from twisted.internet import defer

from synapse import event_auth
from synapse.api.constants import EventTypes, Membership, RejectedReason
from synapse.api.errors import (
    AuthError,
    CodeMessageException,
    Codes,
    FederationDeniedError,
    FederationError,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersion, RoomVersions
from synapse.crypto.event_signing import compute_event_signature
from synapse.event_auth import auth_types_for_event
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.events.validator import EventValidator
from synapse.handlers._base import BaseHandler
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    preserve_fn,
    run_in_background,
)
from synapse.logging.utils import log_function
from synapse.replication.http.devices import ReplicationUserDevicesResyncRestServlet
from synapse.replication.http.federation import (
    ReplicationCleanRoomRestServlet,
    ReplicationFederationSendEventsRestServlet,
    ReplicationStoreRoomOnInviteRestServlet,
)
from synapse.replication.http.membership import ReplicationUserJoinedLeftRoomRestServlet
from synapse.state import StateResolutionStore, resolve_events_with_store
from synapse.storage.data_stores.main.events_worker import EventRedactBehaviour
from synapse.types import JsonDict, StateMap, UserID, get_domain_from_id
from synapse.util.async_helpers import Linearizer, concurrently_execute
from synapse.util.distributor import user_joined_room
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import shortstr
from synapse.visibility import filter_events_for_server

logger = logging.getLogger(__name__)


@attr.s
class _NewEventInfo:
    """Holds information about a received event, ready for passing to _handle_new_events

    Attributes:
        event: the received event

        state: the state at that event

        auth_events: the auth_event map for that event
    """

    event = attr.ib(type=EventBase)
    state = attr.ib(type=Optional[Sequence[EventBase]], default=None)
    auth_events = attr.ib(type=Optional[StateMap[EventBase]], default=None)


class FederationHandler(BaseHandler):
    """Handles events that originated from federation.
        Responsible for:
        a) handling received Pdus before handing them on as Events to the rest
        of the homeserver (including auth and state conflict resoultion)
        b) converting events that were produced by local clients that may need
        to be sent to remote homeservers.
        c) doing the necessary dances to invite remote users and join remote
        rooms.
    """

    def __init__(self, hs):
        super(FederationHandler, self).__init__(hs)

        self.hs = hs

        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state
        self.federation_client = hs.get_federation_client()
        self.state_handler = hs.get_state_handler()
        self.server_name = hs.hostname
        self.keyring = hs.get_keyring()
        self.action_generator = hs.get_action_generator()
        self.is_mine_id = hs.is_mine_id
        self.pusher_pool = hs.get_pusherpool()
        self.spam_checker = hs.get_spam_checker()
        self.event_creation_handler = hs.get_event_creation_handler()
        self._message_handler = hs.get_message_handler()
        self._server_notices_mxid = hs.config.server_notices_mxid
        self.config = hs.config
        self.http_client = hs.get_simple_http_client()
        self._instance_name = hs.get_instance_name()
        self._replication = hs.get_replication_data_handler()

        self._send_events = ReplicationFederationSendEventsRestServlet.make_client(hs)
        self._notify_user_membership_change = ReplicationUserJoinedLeftRoomRestServlet.make_client(
            hs
        )
        self._clean_room_for_join_client = ReplicationCleanRoomRestServlet.make_client(
            hs
        )

        if hs.config.worker_app:
            self._user_device_resync = ReplicationUserDevicesResyncRestServlet.make_client(
                hs
            )
            self._maybe_store_room_on_invite = ReplicationStoreRoomOnInviteRestServlet.make_client(
                hs
            )
        else:
            self._device_list_updater = hs.get_device_handler().device_list_updater
            self._maybe_store_room_on_invite = self.store.maybe_store_room_on_invite

        # When joining a room we need to queue any events for that room up
        self.room_queues = {}
        self._room_pdu_linearizer = Linearizer("fed_room_pdu")

        self.third_party_event_rules = hs.get_third_party_event_rules()

        self._ephemeral_messages_enabled = hs.config.enable_ephemeral_messages

    async def on_receive_pdu(self, origin, pdu, sent_to_us_directly=False) -> None:
        """ Process a PDU received via a federation /send/ transaction, or
        via backfill of missing prev_events

        Args:
            origin (str): server which initiated the /send/ transaction. Will
                be used to fetch missing events or state.
            pdu (FrozenEvent): received PDU
            sent_to_us_directly (bool): True if this event was pushed to us; False if
                we pulled it as the result of a missing prev_event.
        """

        room_id = pdu.room_id
        event_id = pdu.event_id

        logger.info("handling received PDU: %s", pdu)

        # We reprocess pdus when we have seen them only as outliers
        existing = await self.store.get_event(
            event_id, allow_none=True, allow_rejected=True
        )

        # FIXME: Currently we fetch an event again when we already have it
        # if it has been marked as an outlier.

        already_seen = existing and (
            not existing.internal_metadata.is_outlier()
            or pdu.internal_metadata.is_outlier()
        )
        if already_seen:
            logger.debug("[%s %s]: Already seen pdu", room_id, event_id)
            return

        # do some initial sanity-checking of the event. In particular, make
        # sure it doesn't have hundreds of prev_events or auth_events, which
        # could cause a huge state resolution or cascade of event fetches.
        try:
            self._sanity_check_event(pdu)
        except SynapseError as err:
            logger.warning(
                "[%s %s] Received event failed sanity checks", room_id, event_id
            )
            raise FederationError("ERROR", err.code, err.msg, affected=pdu.event_id)

        # If we are currently in the process of joining this room, then we
        # queue up events for later processing.
        if room_id in self.room_queues:
            logger.info(
                "[%s %s] Queuing PDU from %s for now: join in progress",
                room_id,
                event_id,
                origin,
            )
            self.room_queues[room_id].append((pdu, origin))
            return

        # If we're not in the room just ditch the event entirely. This is
        # probably an old server that has come back and thinks we're still in
        # the room (or we've been rejoined to the room by a state reset).
        #
        # Note that if we were never in the room then we would have already
        # dropped the event, since we wouldn't know the room version.
        is_in_room = await self.auth.check_host_in_room(room_id, self.server_name)
        if not is_in_room:
            logger.info(
                "[%s %s] Ignoring PDU from %s as we're not in the room",
                room_id,
                event_id,
                origin,
            )
            return None

        state = None

        # Get missing pdus if necessary.
        if not pdu.internal_metadata.is_outlier():
            # We only backfill backwards to the min depth.
            min_depth = await self.get_min_depth_for_context(pdu.room_id)

            logger.debug("[%s %s] min_depth: %d", room_id, event_id, min_depth)

            prevs = set(pdu.prev_event_ids())
            seen = await self.store.have_seen_events(prevs)

            if min_depth is not None and pdu.depth < min_depth:
                # This is so that we don't notify the user about this
                # message, to work around the fact that some events will
                # reference really really old events we really don't want to
                # send to the clients.
                pdu.internal_metadata.outlier = True
            elif min_depth is not None and pdu.depth > min_depth:
                missing_prevs = prevs - seen
                if sent_to_us_directly and missing_prevs:
                    # If we're missing stuff, ensure we only fetch stuff one
                    # at a time.
                    logger.info(
                        "[%s %s] Acquiring room lock to fetch %d missing prev_events: %s",
                        room_id,
                        event_id,
                        len(missing_prevs),
                        shortstr(missing_prevs),
                    )
                    with (await self._room_pdu_linearizer.queue(pdu.room_id)):
                        logger.info(
                            "[%s %s] Acquired room lock to fetch %d missing prev_events",
                            room_id,
                            event_id,
                            len(missing_prevs),
                        )

                        try:
                            await self._get_missing_events_for_pdu(
                                origin, pdu, prevs, min_depth
                            )
                        except Exception as e:
                            raise Exception(
                                "Error fetching missing prev_events for %s: %s"
                                % (event_id, e)
                            )

                        # Update the set of things we've seen after trying to
                        # fetch the missing stuff
                        seen = await self.store.have_seen_events(prevs)

                        if not prevs - seen:
                            logger.info(
                                "[%s %s] Found all missing prev_events",
                                room_id,
                                event_id,
                            )

            if prevs - seen:
                # We've still not been able to get all of the prev_events for this event.
                #
                # In this case, we need to fall back to asking another server in the
                # federation for the state at this event. That's ok provided we then
                # resolve the state against other bits of the DAG before using it (which
                # will ensure that you can't just take over a room by sending an event,
                # withholding its prev_events, and declaring yourself to be an admin in
                # the subsequent state request).
                #
                # Now, if we're pulling this event as a missing prev_event, then clearly
                # this event is not going to become the only forward-extremity and we are
                # guaranteed to resolve its state against our existing forward
                # extremities, so that should be fine.
                #
                # On the other hand, if this event was pushed to us, it is possible for
                # it to become the only forward-extremity in the room, and we would then
                # trust its state to be the state for the whole room. This is very bad.
                # Further, if the event was pushed to us, there is no excuse for us not to
                # have all the prev_events. We therefore reject any such events.
                #
                # XXX this really feels like it could/should be merged with the above,
                # but there is an interaction with min_depth that I'm not really
                # following.

                if sent_to_us_directly:
                    logger.warning(
                        "[%s %s] Rejecting: failed to fetch %d prev events: %s",
                        room_id,
                        event_id,
                        len(prevs - seen),
                        shortstr(prevs - seen),
                    )
                    raise FederationError(
                        "ERROR",
                        403,
                        (
                            "Your server isn't divulging details about prev_events "
                            "referenced in this event."
                        ),
                        affected=pdu.event_id,
                    )

                logger.info(
                    "Event %s is missing prev_events: calculating state for a "
                    "backwards extremity",
                    event_id,
                )

                # Calculate the state after each of the previous events, and
                # resolve them to find the correct state at the current event.
                event_map = {event_id: pdu}
                try:
                    # Get the state of the events we know about
                    ours = await self.state_store.get_state_groups_ids(room_id, seen)

                    # state_maps is a list of mappings from (type, state_key) to event_id
                    state_maps = list(ours.values())  # type: List[StateMap[str]]

                    # we don't need this any more, let's delete it.
                    del ours

                    # Ask the remote server for the states we don't
                    # know about
                    for p in prevs - seen:
                        logger.info(
                            "Requesting state at missing prev_event %s", event_id,
                        )

                        with nested_logging_context(p):
                            # note that if any of the missing prevs share missing state or
                            # auth events, the requests to fetch those events are deduped
                            # by the get_pdu_cache in federation_client.
                            (remote_state, _,) = await self._get_state_for_room(
                                origin, room_id, p, include_event_in_state=True
                            )

                            remote_state_map = {
                                (x.type, x.state_key): x.event_id for x in remote_state
                            }
                            state_maps.append(remote_state_map)

                            for x in remote_state:
                                event_map[x.event_id] = x

                    room_version = await self.store.get_room_version_id(room_id)
                    state_map = await resolve_events_with_store(
                        room_id,
                        room_version,
                        state_maps,
                        event_map,
                        state_res_store=StateResolutionStore(self.store),
                    )

                    # We need to give _process_received_pdu the actual state events
                    # rather than event ids, so generate that now.

                    # First though we need to fetch all the events that are in
                    # state_map, so we can build up the state below.
                    evs = await self.store.get_events(
                        list(state_map.values()),
                        get_prev_content=False,
                        redact_behaviour=EventRedactBehaviour.AS_IS,
                    )
                    event_map.update(evs)

                    state = [event_map[e] for e in six.itervalues(state_map)]
                except Exception:
                    logger.warning(
                        "[%s %s] Error attempting to resolve state at missing "
                        "prev_events",
                        room_id,
                        event_id,
                        exc_info=True,
                    )
                    raise FederationError(
                        "ERROR",
                        403,
                        "We can't get valid state history.",
                        affected=event_id,
                    )

        await self._process_received_pdu(origin, pdu, state=state)

    async def _get_missing_events_for_pdu(self, origin, pdu, prevs, min_depth):
        """
        Args:
            origin (str): Origin of the pdu. Will be called to get the missing events
            pdu: received pdu
            prevs (set(str)): List of event ids which we are missing
            min_depth (int): Minimum depth of events to return.
        """

        room_id = pdu.room_id
        event_id = pdu.event_id

        seen = await self.store.have_seen_events(prevs)

        if not prevs - seen:
            return

        latest = await self.store.get_latest_event_ids_in_room(room_id)

        # We add the prev events that we have seen to the latest
        # list to ensure the remote server doesn't give them to us
        latest = set(latest)
        latest |= seen

        logger.info(
            "[%s %s]: Requesting missing events between %s and %s",
            room_id,
            event_id,
            shortstr(latest),
            event_id,
        )

        # XXX: we set timeout to 10s to help workaround
        # https://github.com/matrix-org/synapse/issues/1733.
        # The reason is to avoid holding the linearizer lock
        # whilst processing inbound /send transactions, causing
        # FDs to stack up and block other inbound transactions
        # which empirically can currently take up to 30 minutes.
        #
        # N.B. this explicitly disables retry attempts.
        #
        # N.B. this also increases our chances of falling back to
        # fetching fresh state for the room if the missing event
        # can't be found, which slightly reduces our security.
        # it may also increase our DAG extremity count for the room,
        # causing additional state resolution?  See #1760.
        # However, fetching state doesn't hold the linearizer lock
        # apparently.
        #
        # see https://github.com/matrix-org/synapse/pull/1744
        #
        # ----
        #
        # Update richvdh 2018/09/18: There are a number of problems with timing this
        # request out agressively on the client side:
        #
        # - it plays badly with the server-side rate-limiter, which starts tarpitting you
        #   if you send too many requests at once, so you end up with the server carefully
        #   working through the backlog of your requests, which you have already timed
        #   out.
        #
        # - for this request in particular, we now (as of
        #   https://github.com/matrix-org/synapse/pull/3456) reject any PDUs where the
        #   server can't produce a plausible-looking set of prev_events - so we becone
        #   much more likely to reject the event.
        #
        # - contrary to what it says above, we do *not* fall back to fetching fresh state
        #   for the room if get_missing_events times out. Rather, we give up processing
        #   the PDU whose prevs we are missing, which then makes it much more likely that
        #   we'll end up back here for the *next* PDU in the list, which exacerbates the
        #   problem.
        #
        # - the agressive 10s timeout was introduced to deal with incoming federation
        #   requests taking 8 hours to process. It's not entirely clear why that was going
        #   on; certainly there were other issues causing traffic storms which are now
        #   resolved, and I think in any case we may be more sensible about our locking
        #   now. We're *certainly* more sensible about our logging.
        #
        # All that said: Let's try increasing the timout to 60s and see what happens.

        try:
            missing_events = await self.federation_client.get_missing_events(
                origin,
                room_id,
                earliest_events_ids=list(latest),
                latest_events=[pdu],
                limit=10,
                min_depth=min_depth,
                timeout=60000,
            )
        except (RequestSendFailed, HttpResponseException, NotRetryingDestination) as e:
            # We failed to get the missing events, but since we need to handle
            # the case of `get_missing_events` not returning the necessary
            # events anyway, it is safe to simply log the error and continue.
            logger.warning(
                "[%s %s]: Failed to get prev_events: %s", room_id, event_id, e
            )
            return

        logger.info(
            "[%s %s]: Got %d prev_events: %s",
            room_id,
            event_id,
            len(missing_events),
            shortstr(missing_events),
        )

        # We want to sort these by depth so we process them and
        # tell clients about them in order.
        missing_events.sort(key=lambda x: x.depth)

        for ev in missing_events:
            logger.info(
                "[%s %s] Handling received prev_event %s",
                room_id,
                event_id,
                ev.event_id,
            )
            with nested_logging_context(ev.event_id):
                try:
                    await self.on_receive_pdu(origin, ev, sent_to_us_directly=False)
                except FederationError as e:
                    if e.code == 403:
                        logger.warning(
                            "[%s %s] Received prev_event %s failed history check.",
                            room_id,
                            event_id,
                            ev.event_id,
                        )
                    else:
                        raise

    async def _get_state_for_room(
        self,
        destination: str,
        room_id: str,
        event_id: str,
        include_event_in_state: bool = False,
    ) -> Tuple[List[EventBase], List[EventBase]]:
        """Requests all of the room state at a given event from a remote homeserver.

        Args:
            destination: The remote homeserver to query for the state.
            room_id: The id of the room we're interested in.
            event_id: The id of the event we want the state at.
            include_event_in_state: if true, the event itself will be included in the
                returned state event list.

        Returns:
            A list of events in the state, possibly including the event itself, and
            a list of events in the auth chain for the given event.
        """
        (
            state_event_ids,
            auth_event_ids,
        ) = await self.federation_client.get_room_state_ids(
            destination, room_id, event_id=event_id
        )

        desired_events = set(state_event_ids + auth_event_ids)

        if include_event_in_state:
            desired_events.add(event_id)

        event_map = await self._get_events_from_store_or_dest(
            destination, room_id, desired_events
        )

        failed_to_fetch = desired_events - event_map.keys()
        if failed_to_fetch:
            logger.warning(
                "Failed to fetch missing state/auth events for %s %s",
                event_id,
                failed_to_fetch,
            )

        remote_state = [
            event_map[e_id] for e_id in state_event_ids if e_id in event_map
        ]

        if include_event_in_state:
            remote_event = event_map.get(event_id)
            if not remote_event:
                raise Exception("Unable to get missing prev_event %s" % (event_id,))
            if remote_event.is_state() and remote_event.rejected_reason is None:
                remote_state.append(remote_event)

        auth_chain = [event_map[e_id] for e_id in auth_event_ids if e_id in event_map]
        auth_chain.sort(key=lambda e: e.depth)

        return remote_state, auth_chain

    async def _get_events_from_store_or_dest(
        self, destination: str, room_id: str, event_ids: Iterable[str]
    ) -> Dict[str, EventBase]:
        """Fetch events from a remote destination, checking if we already have them.

        Persists any events we don't already have as outliers.

        If we fail to fetch any of the events, a warning will be logged, and the event
        will be omitted from the result. Likewise, any events which turn out not to
        be in the given room.

        Returns:
            map from event_id to event
        """
        fetched_events = await self.store.get_events(event_ids, allow_rejected=True)

        missing_events = set(event_ids) - fetched_events.keys()

        if missing_events:
            logger.debug(
                "Fetching unknown state/auth events %s for room %s",
                missing_events,
                room_id,
            )

            await self._get_events_and_persist(
                destination=destination, room_id=room_id, events=missing_events
            )

            # we need to make sure we re-load from the database to get the rejected
            # state correct.
            fetched_events.update(
                (await self.store.get_events(missing_events, allow_rejected=True))
            )

        # check for events which were in the wrong room.
        #
        # this can happen if a remote server claims that the state or
        # auth_events at an event in room A are actually events in room B

        bad_events = [
            (event_id, event.room_id)
            for event_id, event in fetched_events.items()
            if event.room_id != room_id
        ]

        for bad_event_id, bad_room_id in bad_events:
            # This is a bogus situation, but since we may only discover it a long time
            # after it happened, we try our best to carry on, by just omitting the
            # bad events from the returned auth/state set.
            logger.warning(
                "Remote server %s claims event %s in room %s is an auth/state "
                "event in room %s",
                destination,
                bad_event_id,
                bad_room_id,
                room_id,
            )

            del fetched_events[bad_event_id]

        return fetched_events

    async def _process_received_pdu(
        self, origin: str, event: EventBase, state: Optional[Iterable[EventBase]],
    ):
        """ Called when we have a new pdu. We need to do auth checks and put it
        through the StateHandler.

        Args:
            origin: server sending the event

            event: event to be persisted

            state: Normally None, but if we are handling a gap in the graph
                (ie, we are missing one or more prev_events), the resolved state at the
                event
        """
        room_id = event.room_id
        event_id = event.event_id

        logger.debug("[%s %s] Processing event: %s", room_id, event_id, event)

        try:
            context = await self._handle_new_event(origin, event, state=state)
        except AuthError as e:
            raise FederationError("ERROR", e.code, e.msg, affected=event.event_id)

        if event.type == EventTypes.Member:
            if event.membership == Membership.JOIN:
                # Only fire user_joined_room if the user has acutally
                # joined the room. Don't bother if the user is just
                # changing their profile info.
                newly_joined = True

                prev_state_ids = await context.get_prev_state_ids()

                prev_state_id = prev_state_ids.get((event.type, event.state_key))
                if prev_state_id:
                    prev_state = await self.store.get_event(
                        prev_state_id, allow_none=True
                    )
                    if prev_state and prev_state.membership == Membership.JOIN:
                        newly_joined = False

                if newly_joined:
                    user = UserID.from_string(event.state_key)
                    await self.user_joined_room(user, room_id)

        # For encrypted messages we check that we know about the sending device,
        # if we don't then we mark the device cache for that user as stale.
        if event.type == EventTypes.Encrypted:
            device_id = event.content.get("device_id")
            sender_key = event.content.get("sender_key")

            cached_devices = await self.store.get_cached_devices_for_user(event.sender)

            resync = False  # Whether we should resync device lists.

            device = None
            if device_id is not None:
                device = cached_devices.get(device_id)
                if device is None:
                    logger.info(
                        "Received event from remote device not in our cache: %s %s",
                        event.sender,
                        device_id,
                    )
                    resync = True

            # We also check if the `sender_key` matches what we expect.
            if sender_key is not None:
                # Figure out what sender key we're expecting. If we know the
                # device and recognize the algorithm then we can work out the
                # exact key to expect. Otherwise check it matches any key we
                # have for that device.
                if device:
                    keys = device.get("keys", {}).get("keys", {})

                    if event.content.get("algorithm") == "m.megolm.v1.aes-sha2":
                        # For this algorithm we expect a curve25519 key.
                        key_name = "curve25519:%s" % (device_id,)
                        current_keys = [keys.get(key_name)]
                    else:
                        # We don't know understand the algorithm, so we just
                        # check it matches a key for the device.
                        current_keys = keys.values()
                elif device_id:
                    # We don't have any keys for the device ID.
                    current_keys = []
                else:
                    # The event didn't include a device ID, so we just look for
                    # keys across all devices.
                    current_keys = (
                        key
                        for device in cached_devices
                        for key in device.get("keys", {}).get("keys", {}).values()
                    )

                # We now check that the sender key matches (one of) the expected
                # keys.
                if sender_key not in current_keys:
                    logger.info(
                        "Received event from remote device with unexpected sender key: %s %s: %s",
                        event.sender,
                        device_id or "<no device_id>",
                        sender_key,
                    )
                    resync = True

            if resync:
                await self.store.mark_remote_user_device_cache_as_stale(event.sender)

                # Immediately attempt a resync in the background
                if self.config.worker_app:
                    return run_in_background(self._user_device_resync, event.sender)
                else:
                    return run_in_background(
                        self._device_list_updater.user_device_resync, event.sender
                    )

    @log_function
    async def backfill(self, dest, room_id, limit, extremities):
        """ Trigger a backfill request to `dest` for the given `room_id`

        This will attempt to get more events from the remote. If the other side
        has no new events to offer, this will return an empty list.

        As the events are received, we check their signatures, and also do some
        sanity-checking on them. If any of the backfilled events are invalid,
        this method throws a SynapseError.

        TODO: make this more useful to distinguish failures of the remote
        server from invalid events (there is probably no point in trying to
        re-fetch invalid events from every other HS in the room.)
        """
        if dest == self.server_name:
            raise SynapseError(400, "Can't backfill from self.")

        events = await self.federation_client.backfill(
            dest, room_id, limit=limit, extremities=extremities
        )

        # ideally we'd sanity check the events here for excess prev_events etc,
        # but it's hard to reject events at this point without completely
        # breaking backfill in the same way that it is currently broken by
        # events whose signature we cannot verify (#3121).
        #
        # So for now we accept the events anyway. #3124 tracks this.
        #
        # for ev in events:
        #     self._sanity_check_event(ev)

        # Don't bother processing events we already have.
        seen_events = await self.store.have_events_in_timeline(
            {e.event_id for e in events}
        )

        events = [e for e in events if e.event_id not in seen_events]

        if not events:
            return []

        event_map = {e.event_id: e for e in events}

        event_ids = {e.event_id for e in events}

        # build a list of events whose prev_events weren't in the batch.
        # (XXX: this will include events whose prev_events we already have; that doesn't
        # sound right?)
        edges = [ev.event_id for ev in events if set(ev.prev_event_ids()) - event_ids]

        logger.info("backfill: Got %d events with %d edges", len(events), len(edges))

        # For each edge get the current state.

        auth_events = {}
        state_events = {}
        events_to_state = {}
        for e_id in edges:
            state, auth = await self._get_state_for_room(
                destination=dest,
                room_id=room_id,
                event_id=e_id,
                include_event_in_state=False,
            )
            auth_events.update({a.event_id: a for a in auth})
            auth_events.update({s.event_id: s for s in state})
            state_events.update({s.event_id: s for s in state})
            events_to_state[e_id] = state

        required_auth = {
            a_id
            for event in events
            + list(state_events.values())
            + list(auth_events.values())
            for a_id in event.auth_event_ids()
        }
        auth_events.update(
            {e_id: event_map[e_id] for e_id in required_auth if e_id in event_map}
        )

        ev_infos = []

        # Step 1: persist the events in the chunk we fetched state for (i.e.
        # the backwards extremities), with custom auth events and state
        for e_id in events_to_state:
            # For paranoia we ensure that these events are marked as
            # non-outliers
            ev = event_map[e_id]
            assert not ev.internal_metadata.is_outlier()

            ev_infos.append(
                _NewEventInfo(
                    event=ev,
                    state=events_to_state[e_id],
                    auth_events={
                        (
                            auth_events[a_id].type,
                            auth_events[a_id].state_key,
                        ): auth_events[a_id]
                        for a_id in ev.auth_event_ids()
                        if a_id in auth_events
                    },
                )
            )

        await self._handle_new_events(dest, ev_infos, backfilled=True)

        # Step 2: Persist the rest of the events in the chunk one by one
        events.sort(key=lambda e: e.depth)

        for event in events:
            if event in events_to_state:
                continue

            # For paranoia we ensure that these events are marked as
            # non-outliers
            assert not event.internal_metadata.is_outlier()

            # We store these one at a time since each event depends on the
            # previous to work out the state.
            # TODO: We can probably do something more clever here.
            await self._handle_new_event(dest, event, backfilled=True)

        return events

    async def maybe_backfill(self, room_id, current_depth):
        """Checks the database to see if we should backfill before paginating,
        and if so do.
        """
        extremities = await self.store.get_oldest_events_with_depth_in_room(room_id)

        if not extremities:
            logger.debug("Not backfilling as no extremeties found.")
            return

        # We only want to paginate if we can actually see the events we'll get,
        # as otherwise we'll just spend a lot of resources to get redacted
        # events.
        #
        # We do this by filtering all the backwards extremities and seeing if
        # any remain. Given we don't have the extremity events themselves, we
        # need to actually check the events that reference them.
        #
        # *Note*: the spec wants us to keep backfilling until we reach the start
        # of the room in case we are allowed to see some of the history. However
        # in practice that causes more issues than its worth, as a) its
        # relatively rare for there to be any visible history and b) even when
        # there is its often sufficiently long ago that clients would stop
        # attempting to paginate before backfill reached the visible history.
        #
        # TODO: If we do do a backfill then we should filter the backwards
        #   extremities to only include those that point to visible portions of
        #   history.
        #
        # TODO: Correctly handle the case where we are allowed to see the
        #   forward event but not the backward extremity, e.g. in the case of
        #   initial join of the server where we are allowed to see the join
        #   event but not anything before it. This would require looking at the
        #   state *before* the event, ignoring the special casing certain event
        #   types have.

        forward_events = await self.store.get_successor_events(list(extremities))

        extremities_events = await self.store.get_events(
            forward_events,
            redact_behaviour=EventRedactBehaviour.AS_IS,
            get_prev_content=False,
        )

        # We set `check_history_visibility_only` as we might otherwise get false
        # positives from users having been erased.
        filtered_extremities = await filter_events_for_server(
            self.storage,
            self.server_name,
            list(extremities_events.values()),
            redact=False,
            check_history_visibility_only=True,
        )

        if not filtered_extremities:
            return False

        # Check if we reached a point where we should start backfilling.
        sorted_extremeties_tuple = sorted(extremities.items(), key=lambda e: -int(e[1]))
        max_depth = sorted_extremeties_tuple[0][1]

        # We don't want to specify too many extremities as it causes the backfill
        # request URI to be too long.
        extremities = dict(sorted_extremeties_tuple[:5])

        if current_depth > max_depth:
            logger.debug(
                "Not backfilling as we don't need to. %d < %d", max_depth, current_depth
            )
            return

        # Now we need to decide which hosts to hit first.

        # First we try hosts that are already in the room
        # TODO: HEURISTIC ALERT.

        curr_state = await self.state_handler.get_current_state(room_id)

        def get_domains_from_state(state):
            """Get joined domains from state

            Args:
                state (dict[tuple, FrozenEvent]): State map from type/state
                    key to event.

            Returns:
                list[tuple[str, int]]: Returns a list of servers with the
                lowest depth of their joins. Sorted by lowest depth first.
            """
            joined_users = [
                (state_key, int(event.depth))
                for (e_type, state_key), event in iteritems(state)
                if e_type == EventTypes.Member and event.membership == Membership.JOIN
            ]

            joined_domains = {}
            for u, d in joined_users:
                try:
                    dom = get_domain_from_id(u)
                    old_d = joined_domains.get(dom)
                    if old_d:
                        joined_domains[dom] = min(d, old_d)
                    else:
                        joined_domains[dom] = d
                except Exception:
                    pass

            return sorted(joined_domains.items(), key=lambda d: d[1])

        curr_domains = get_domains_from_state(curr_state)

        likely_domains = [
            domain for domain, depth in curr_domains if domain != self.server_name
        ]

        async def try_backfill(domains):
            # TODO: Should we try multiple of these at a time?
            for dom in domains:
                try:
                    await self.backfill(
                        dom, room_id, limit=100, extremities=extremities
                    )
                    # If this succeeded then we probably already have the
                    # appropriate stuff.
                    # TODO: We can probably do something more intelligent here.
                    return True
                except SynapseError as e:
                    logger.info("Failed to backfill from %s because %s", dom, e)
                    continue
                except HttpResponseException as e:
                    if 400 <= e.code < 500:
                        raise e.to_synapse_error()

                    logger.info("Failed to backfill from %s because %s", dom, e)
                    continue
                except CodeMessageException as e:
                    if 400 <= e.code < 500:
                        raise

                    logger.info("Failed to backfill from %s because %s", dom, e)
                    continue
                except NotRetryingDestination as e:
                    logger.info(str(e))
                    continue
                except RequestSendFailed as e:
                    logger.info("Falied to get backfill from %s because %s", dom, e)
                    continue
                except FederationDeniedError as e:
                    logger.info(e)
                    continue
                except Exception as e:
                    logger.exception("Failed to backfill from %s because %s", dom, e)
                    continue

            return False

        success = await try_backfill(likely_domains)
        if success:
            return True

        # Huh, well *those* domains didn't work out. Lets try some domains
        # from the time.

        tried_domains = set(likely_domains)
        tried_domains.add(self.server_name)

        event_ids = list(extremities.keys())

        logger.debug("calling resolve_state_groups in _maybe_backfill")
        resolve = preserve_fn(self.state_handler.resolve_state_groups_for_events)
        states = await make_deferred_yieldable(
            defer.gatherResults(
                [resolve(room_id, [e]) for e in event_ids], consumeErrors=True
            )
        )

        # dict[str, dict[tuple, str]], a map from event_id to state map of
        # event_ids.
        states = dict(zip(event_ids, [s.state for s in states]))

        state_map = await self.store.get_events(
            [e_id for ids in itervalues(states) for e_id in itervalues(ids)],
            get_prev_content=False,
        )
        states = {
            key: {
                k: state_map[e_id]
                for k, e_id in iteritems(state_dict)
                if e_id in state_map
            }
            for key, state_dict in iteritems(states)
        }

        for e_id, _ in sorted_extremeties_tuple:
            likely_domains = get_domains_from_state(states[e_id])

            success = await try_backfill(
                [dom for dom, _ in likely_domains if dom not in tried_domains]
            )
            if success:
                return True

            tried_domains.update(dom for dom, _ in likely_domains)

        return False

    async def _get_events_and_persist(
        self, destination: str, room_id: str, events: Iterable[str]
    ):
        """Fetch the given events from a server, and persist them as outliers.

        Logs a warning if we can't find the given event.
        """

        room_version = await self.store.get_room_version(room_id)

        event_infos = []

        async def get_event(event_id: str):
            with nested_logging_context(event_id):
                try:
                    event = await self.federation_client.get_pdu(
                        [destination], event_id, room_version, outlier=True,
                    )
                    if event is None:
                        logger.warning(
                            "Server %s didn't return event %s", destination, event_id,
                        )
                        return

                    # recursively fetch the auth events for this event
                    auth_events = await self._get_events_from_store_or_dest(
                        destination, room_id, event.auth_event_ids()
                    )
                    auth = {}
                    for auth_event_id in event.auth_event_ids():
                        ae = auth_events.get(auth_event_id)
                        if ae:
                            auth[(ae.type, ae.state_key)] = ae

                    event_infos.append(_NewEventInfo(event, None, auth))

                except Exception as e:
                    logger.warning(
                        "Error fetching missing state/auth event %s: %s %s",
                        event_id,
                        type(e),
                        e,
                    )

        await concurrently_execute(get_event, events, 5)

        await self._handle_new_events(
            destination, event_infos,
        )

    def _sanity_check_event(self, ev):
        """
        Do some early sanity checks of a received event

        In particular, checks it doesn't have an excessive number of
        prev_events or auth_events, which could cause a huge state resolution
        or cascade of event fetches.

        Args:
            ev (synapse.events.EventBase): event to be checked

        Returns: None

        Raises:
            SynapseError if the event does not pass muster
        """
        if len(ev.prev_event_ids()) > 20:
            logger.warning(
                "Rejecting event %s which has %i prev_events",
                ev.event_id,
                len(ev.prev_event_ids()),
            )
            raise SynapseError(http_client.BAD_REQUEST, "Too many prev_events")

        if len(ev.auth_event_ids()) > 10:
            logger.warning(
                "Rejecting event %s which has %i auth_events",
                ev.event_id,
                len(ev.auth_event_ids()),
            )
            raise SynapseError(http_client.BAD_REQUEST, "Too many auth_events")

    async def send_invite(self, target_host, event):
        """ Sends the invite to the remote server for signing.

        Invites must be signed by the invitee's server before distribution.
        """
        pdu = await self.federation_client.send_invite(
            destination=target_host,
            room_id=event.room_id,
            event_id=event.event_id,
            pdu=event,
        )

        return pdu

    async def on_event_auth(self, event_id: str) -> List[EventBase]:
        event = await self.store.get_event(event_id)
        auth = await self.store.get_auth_chain(
            list(event.auth_event_ids()), include_given=True
        )
        return list(auth)

    async def do_invite_join(
        self, target_hosts: Iterable[str], room_id: str, joinee: str, content: JsonDict
    ) -> Tuple[str, int]:
        """ Attempts to join the `joinee` to the room `room_id` via the
        servers contained in `target_hosts`.

        This first triggers a /make_join/ request that returns a partial
        event that we can fill out and sign. This is then sent to the
        remote server via /send_join/ which responds with the state at that
        event and the auth_chains.

        We suspend processing of any received events from this room until we
        have finished processing the join.

        Args:
            target_hosts: List of servers to attempt to join the room with.

            room_id: The ID of the room to join.

            joinee: The User ID of the joining user.

            content: The event content to use for the join event.
        """
        # TODO: We should be able to call this on workers, but the upgrading of
        # room stuff after join currently doesn't work on workers.
        assert self.config.worker.worker_app is None

        logger.debug("Joining %s to %s", joinee, room_id)

        origin, event, room_version_obj = await self._make_and_verify_event(
            target_hosts,
            room_id,
            joinee,
            "join",
            content,
            params={"ver": KNOWN_ROOM_VERSIONS},
        )

        # This shouldn't happen, because the RoomMemberHandler has a
        # linearizer lock which only allows one operation per user per room
        # at a time - so this is just paranoia.
        assert room_id not in self.room_queues

        self.room_queues[room_id] = []

        await self._clean_room_for_join(room_id)

        handled_events = set()

        try:
            # Try the host we successfully got a response to /make_join/
            # request first.
            try:
                target_hosts.remove(origin)
                target_hosts.insert(0, origin)
            except ValueError:
                pass

            ret = await self.federation_client.send_join(
                target_hosts, event, room_version_obj
            )

            origin = ret["origin"]
            state = ret["state"]
            auth_chain = ret["auth_chain"]
            auth_chain.sort(key=lambda e: e.depth)

            handled_events.update([s.event_id for s in state])
            handled_events.update([a.event_id for a in auth_chain])
            handled_events.add(event.event_id)

            logger.debug("do_invite_join auth_chain: %s", auth_chain)
            logger.debug("do_invite_join state: %s", state)

            logger.debug("do_invite_join event: %s", event)

            # if this is the first time we've joined this room, it's time to add
            # a row to `rooms` with the correct room version. If there's already a
            # row there, we should override it, since it may have been populated
            # based on an invite request which lied about the room version.
            #
            # federation_client.send_join has already checked that the room
            # version in the received create event is the same as room_version_obj,
            # so we can rely on it now.
            #
            await self.store.upsert_room_on_join(
                room_id=room_id, room_version=room_version_obj,
            )

            max_stream_id = await self._persist_auth_tree(
                origin, auth_chain, state, event, room_version_obj
            )

            # We wait here until this instance has seen the events come down
            # replication (if we're using replication) as the below uses caches.
            #
            # TODO: Currently the events stream is written to from master
            await self._replication.wait_for_stream_position(
                self.config.worker.writers.events, "events", max_stream_id
            )

            # Check whether this room is the result of an upgrade of a room we already know
            # about. If so, migrate over user information
            predecessor = await self.store.get_room_predecessor(room_id)
            if not predecessor or not isinstance(predecessor.get("room_id"), str):
                return event.event_id, max_stream_id
            old_room_id = predecessor["room_id"]
            logger.debug(
                "Found predecessor for %s during remote join: %s", room_id, old_room_id
            )

            # We retrieve the room member handler here as to not cause a cyclic dependency
            member_handler = self.hs.get_room_member_handler()
            await member_handler.transfer_room_state_on_room_upgrade(
                old_room_id, room_id
            )

            logger.debug("Finished joining %s to %s", joinee, room_id)
            return event.event_id, max_stream_id
        finally:
            room_queue = self.room_queues[room_id]
            del self.room_queues[room_id]

            # we don't need to wait for the queued events to be processed -
            # it's just a best-effort thing at this point. We do want to do
            # them roughly in order, though, otherwise we'll end up making
            # lots of requests for missing prev_events which we do actually
            # have. Hence we fire off the deferred, but don't wait for it.

            run_in_background(self._handle_queued_pdus, room_queue)

    async def _handle_queued_pdus(self, room_queue):
        """Process PDUs which got queued up while we were busy send_joining.

        Args:
            room_queue (list[FrozenEvent, str]): list of PDUs to be processed
                and the servers that sent them
        """
        for p, origin in room_queue:
            try:
                logger.info(
                    "Processing queued PDU %s which was received "
                    "while we were joining %s",
                    p.event_id,
                    p.room_id,
                )
                with nested_logging_context(p.event_id):
                    await self.on_receive_pdu(origin, p, sent_to_us_directly=True)
            except Exception as e:
                logger.warning(
                    "Error handling queued PDU %s from %s: %s", p.event_id, origin, e
                )

    async def on_make_join_request(
        self, origin: str, room_id: str, user_id: str
    ) -> EventBase:
        """ We've received a /make_join/ request, so we create a partial
        join event for the room and return that. We do *not* persist or
        process it until the other server has signed it and sent it back.

        Args:
            origin: The (verified) server name of the requesting server.
            room_id: Room to create join event in
            user_id: The user to create the join for
        """
        if get_domain_from_id(user_id) != origin:
            logger.info(
                "Got /make_join request for user %r from different origin %s, ignoring",
                user_id,
                origin,
            )
            raise SynapseError(403, "User not from origin", Codes.FORBIDDEN)

        event_content = {"membership": Membership.JOIN}

        room_version = await self.store.get_room_version_id(room_id)

        builder = self.event_builder_factory.new(
            room_version,
            {
                "type": EventTypes.Member,
                "content": event_content,
                "room_id": room_id,
                "sender": user_id,
                "state_key": user_id,
            },
        )

        try:
            event, context = await self.event_creation_handler.create_new_client_event(
                builder=builder
            )
        except AuthError as e:
            logger.warning("Failed to create join to %s because %s", room_id, e)
            raise e

        event_allowed = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not event_allowed:
            logger.info("Creation of join %s forbidden by third-party rules", event)
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )

        # The remote hasn't signed it yet, obviously. We'll do the full checks
        # when we get the event back in `on_send_join_request`
        await self.auth.check_from_context(
            room_version, event, context, do_sig_check=False
        )

        return event

    async def on_send_join_request(self, origin, pdu):
        """ We have received a join event for a room. Fully process it and
        respond with the current state and auth chains.
        """
        event = pdu

        logger.debug(
            "on_send_join_request from %s: Got event: %s, signatures: %s",
            origin,
            event.event_id,
            event.signatures,
        )

        if get_domain_from_id(event.sender) != origin:
            logger.info(
                "Got /send_join request for user %r from different origin %s",
                event.sender,
                origin,
            )
            raise SynapseError(403, "User not from origin", Codes.FORBIDDEN)

        event.internal_metadata.outlier = False
        # Send this event on behalf of the origin server.
        #
        # The reasons we have the destination server rather than the origin
        # server send it are slightly mysterious: the origin server should have
        # all the neccessary state once it gets the response to the send_join,
        # so it could send the event itself if it wanted to. It may be that
        # doing it this way reduces failure modes, or avoids certain attacks
        # where a new server selectively tells a subset of the federation that
        # it has joined.
        #
        # The fact is that, as of the current writing, Synapse doesn't send out
        # the join event over federation after joining, and changing it now
        # would introduce the danger of backwards-compatibility problems.
        event.internal_metadata.send_on_behalf_of = origin

        context = await self._handle_new_event(origin, event)

        event_allowed = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not event_allowed:
            logger.info("Sending of join %s forbidden by third-party rules", event)
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )

        logger.debug(
            "on_send_join_request: After _handle_new_event: %s, sigs: %s",
            event.event_id,
            event.signatures,
        )

        if event.type == EventTypes.Member:
            if event.content["membership"] == Membership.JOIN:
                user = UserID.from_string(event.state_key)
                await self.user_joined_room(user, event.room_id)

        prev_state_ids = await context.get_prev_state_ids()

        state_ids = list(prev_state_ids.values())
        auth_chain = await self.store.get_auth_chain(state_ids)

        state = await self.store.get_events(list(prev_state_ids.values()))

        return {"state": list(state.values()), "auth_chain": auth_chain}

    async def on_invite_request(
        self, origin: str, event: EventBase, room_version: RoomVersion
    ):
        """ We've got an invite event. Process and persist it. Sign it.

        Respond with the now signed event.
        """
        if event.state_key is None:
            raise SynapseError(400, "The invite event did not have a state key")

        is_blocked = await self.store.is_room_blocked(event.room_id)
        if is_blocked:
            raise SynapseError(403, "This room has been blocked on this server")

        if self.hs.config.block_non_admin_invites:
            raise SynapseError(403, "This server does not accept room invites")

        if not self.spam_checker.user_may_invite(
            event.sender, event.state_key, event.room_id
        ):
            raise SynapseError(
                403, "This user is not permitted to send invites to this server/user"
            )

        membership = event.content.get("membership")
        if event.type != EventTypes.Member or membership != Membership.INVITE:
            raise SynapseError(400, "The event was not an m.room.member invite event")

        sender_domain = get_domain_from_id(event.sender)
        if sender_domain != origin:
            raise SynapseError(
                400, "The invite event was not from the server sending it"
            )

        if not self.is_mine_id(event.state_key):
            raise SynapseError(400, "The invite event must be for this server")

        # block any attempts to invite the server notices mxid
        if event.state_key == self._server_notices_mxid:
            raise SynapseError(http_client.FORBIDDEN, "Cannot invite this user")

        # keep a record of the room version, if we don't yet know it.
        # (this may get overwritten if we later get a different room version in a
        # join dance).
        await self._maybe_store_room_on_invite(
            room_id=event.room_id, room_version=room_version
        )

        event.internal_metadata.outlier = True
        event.internal_metadata.out_of_band_membership = True

        event.signatures.update(
            compute_event_signature(
                room_version,
                event.get_pdu_json(),
                self.hs.hostname,
                self.hs.config.signing_key[0],
            )
        )

        context = await self.state_handler.compute_event_context(event)
        await self.persist_events_and_notify([(event, context)])

        return event

    async def do_remotely_reject_invite(
        self, target_hosts: Iterable[str], room_id: str, user_id: str, content: JsonDict
    ) -> Tuple[EventBase, int]:
        origin, event, room_version = await self._make_and_verify_event(
            target_hosts, room_id, user_id, "leave", content=content
        )
        # Mark as outlier as we don't have any state for this event; we're not
        # even in the room.
        event.internal_metadata.outlier = True
        event.internal_metadata.out_of_band_membership = True

        # Try the host that we succesfully called /make_leave/ on first for
        # the /send_leave/ request.
        try:
            target_hosts.remove(origin)
            target_hosts.insert(0, origin)
        except ValueError:
            pass

        await self.federation_client.send_leave(target_hosts, event)

        context = await self.state_handler.compute_event_context(event)
        stream_id = await self.persist_events_and_notify([(event, context)])

        return event, stream_id

    async def _make_and_verify_event(
        self,
        target_hosts: Iterable[str],
        room_id: str,
        user_id: str,
        membership: str,
        content: JsonDict = {},
        params: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, EventBase, RoomVersion]:
        (
            origin,
            event,
            room_version,
        ) = await self.federation_client.make_membership_event(
            target_hosts, room_id, user_id, membership, content, params=params
        )

        logger.debug("Got response to make_%s: %s", membership, event)

        # We should assert some things.
        # FIXME: Do this in a nicer way
        assert event.type == EventTypes.Member
        assert event.user_id == user_id
        assert event.state_key == user_id
        assert event.room_id == room_id
        return origin, event, room_version

    async def on_make_leave_request(
        self, origin: str, room_id: str, user_id: str
    ) -> EventBase:
        """ We've received a /make_leave/ request, so we create a partial
        leave event for the room and return that. We do *not* persist or
        process it until the other server has signed it and sent it back.

        Args:
            origin: The (verified) server name of the requesting server.
            room_id: Room to create leave event in
            user_id: The user to create the leave for
        """
        if get_domain_from_id(user_id) != origin:
            logger.info(
                "Got /make_leave request for user %r from different origin %s, ignoring",
                user_id,
                origin,
            )
            raise SynapseError(403, "User not from origin", Codes.FORBIDDEN)

        room_version = await self.store.get_room_version_id(room_id)
        builder = self.event_builder_factory.new(
            room_version,
            {
                "type": EventTypes.Member,
                "content": {"membership": Membership.LEAVE},
                "room_id": room_id,
                "sender": user_id,
                "state_key": user_id,
            },
        )

        event, context = await self.event_creation_handler.create_new_client_event(
            builder=builder
        )

        event_allowed = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not event_allowed:
            logger.warning("Creation of leave %s forbidden by third-party rules", event)
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )

        try:
            # The remote hasn't signed it yet, obviously. We'll do the full checks
            # when we get the event back in `on_send_leave_request`
            await self.auth.check_from_context(
                room_version, event, context, do_sig_check=False
            )
        except AuthError as e:
            logger.warning("Failed to create new leave %r because %s", event, e)
            raise e

        return event

    async def on_send_leave_request(self, origin, pdu):
        """ We have received a leave event for a room. Fully process it."""
        event = pdu

        logger.debug(
            "on_send_leave_request: Got event: %s, signatures: %s",
            event.event_id,
            event.signatures,
        )

        if get_domain_from_id(event.sender) != origin:
            logger.info(
                "Got /send_leave request for user %r from different origin %s",
                event.sender,
                origin,
            )
            raise SynapseError(403, "User not from origin", Codes.FORBIDDEN)

        event.internal_metadata.outlier = False

        context = await self._handle_new_event(origin, event)

        event_allowed = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not event_allowed:
            logger.info("Sending of leave %s forbidden by third-party rules", event)
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )

        logger.debug(
            "on_send_leave_request: After _handle_new_event: %s, sigs: %s",
            event.event_id,
            event.signatures,
        )

        return None

    async def get_state_for_pdu(self, room_id: str, event_id: str) -> List[EventBase]:
        """Returns the state at the event. i.e. not including said event.
        """

        event = await self.store.get_event(
            event_id, allow_none=False, check_room_id=room_id
        )

        state_groups = await self.state_store.get_state_groups(room_id, [event_id])

        if state_groups:
            _, state = list(iteritems(state_groups)).pop()
            results = {(e.type, e.state_key): e for e in state}

            if event.is_state():
                # Get previous state
                if "replaces_state" in event.unsigned:
                    prev_id = event.unsigned["replaces_state"]
                    if prev_id != event.event_id:
                        prev_event = await self.store.get_event(prev_id)
                        results[(event.type, event.state_key)] = prev_event
                else:
                    del results[(event.type, event.state_key)]

            res = list(results.values())
            return res
        else:
            return []

    async def get_state_ids_for_pdu(self, room_id: str, event_id: str) -> List[str]:
        """Returns the state at the event. i.e. not including said event.
        """
        event = await self.store.get_event(
            event_id, allow_none=False, check_room_id=room_id
        )

        state_groups = await self.state_store.get_state_groups_ids(room_id, [event_id])

        if state_groups:
            _, state = list(state_groups.items()).pop()
            results = state

            if event.is_state():
                # Get previous state
                if "replaces_state" in event.unsigned:
                    prev_id = event.unsigned["replaces_state"]
                    if prev_id != event.event_id:
                        results[(event.type, event.state_key)] = prev_id
                else:
                    results.pop((event.type, event.state_key), None)

            return list(results.values())
        else:
            return []

    @log_function
    async def on_backfill_request(
        self, origin: str, room_id: str, pdu_list: List[str], limit: int
    ) -> List[EventBase]:
        in_room = await self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        # Synapse asks for 100 events per backfill request. Do not allow more.
        limit = min(limit, 100)

        events = await self.store.get_backfill_events(room_id, pdu_list, limit)

        events = await filter_events_for_server(self.storage, origin, events)

        return events

    @log_function
    async def get_persisted_pdu(
        self, origin: str, event_id: str
    ) -> Optional[EventBase]:
        """Get an event from the database for the given server.

        Args:
            origin: hostname of server which is requesting the event; we
               will check that the server is allowed to see it.
            event_id: id of the event being requested

        Returns:
            None if we know nothing about the event; otherwise the (possibly-redacted) event.

        Raises:
            AuthError if the server is not currently in the room
        """
        event = await self.store.get_event(
            event_id, allow_none=True, allow_rejected=True
        )

        if event:
            in_room = await self.auth.check_host_in_room(event.room_id, origin)
            if not in_room:
                raise AuthError(403, "Host not in room.")

            events = await filter_events_for_server(self.storage, origin, [event])
            event = events[0]
            return event
        else:
            return None

    def get_min_depth_for_context(self, context):
        return self.store.get_min_depth(context)

    async def _handle_new_event(
        self, origin, event, state=None, auth_events=None, backfilled=False
    ):
        context = await self._prep_event(
            origin, event, state=state, auth_events=auth_events, backfilled=backfilled
        )

        # reraise does not allow inlineCallbacks to preserve the stacktrace, so we
        # hack around with a try/finally instead.
        success = False
        try:
            if (
                not event.internal_metadata.is_outlier()
                and not backfilled
                and not context.rejected
            ):
                await self.action_generator.handle_push_actions_for_event(
                    event, context
                )

            await self.persist_events_and_notify(
                [(event, context)], backfilled=backfilled
            )
            success = True
        finally:
            if not success:
                run_in_background(
                    self.store.remove_push_actions_from_staging, event.event_id
                )

        return context

    async def _handle_new_events(
        self,
        origin: str,
        event_infos: Iterable[_NewEventInfo],
        backfilled: bool = False,
    ) -> None:
        """Creates the appropriate contexts and persists events. The events
        should not depend on one another, e.g. this should be used to persist
        a bunch of outliers, but not a chunk of individual events that depend
        on each other for state calculations.

        Notifies about the events where appropriate.
        """

        async def prep(ev_info: _NewEventInfo):
            event = ev_info.event
            with nested_logging_context(suffix=event.event_id):
                res = await self._prep_event(
                    origin,
                    event,
                    state=ev_info.state,
                    auth_events=ev_info.auth_events,
                    backfilled=backfilled,
                )
            return res

        contexts = await make_deferred_yieldable(
            defer.gatherResults(
                [run_in_background(prep, ev_info) for ev_info in event_infos],
                consumeErrors=True,
            )
        )

        await self.persist_events_and_notify(
            [
                (ev_info.event, context)
                for ev_info, context in zip(event_infos, contexts)
            ],
            backfilled=backfilled,
        )

    async def _persist_auth_tree(
        self,
        origin: str,
        auth_events: List[EventBase],
        state: List[EventBase],
        event: EventBase,
        room_version: RoomVersion,
    ) -> int:
        """Checks the auth chain is valid (and passes auth checks) for the
        state and event. Then persists the auth chain and state atomically.
        Persists the event separately. Notifies about the persisted events
        where appropriate.

        Will attempt to fetch missing auth events.

        Args:
            origin: Where the events came from
            auth_events
            state
            event
            room_version: The room version we expect this room to have, and
                will raise if it doesn't match the version in the create event.
        """
        events_to_context = {}
        for e in itertools.chain(auth_events, state):
            e.internal_metadata.outlier = True
            ctx = await self.state_handler.compute_event_context(e)
            events_to_context[e.event_id] = ctx

        event_map = {
            e.event_id: e for e in itertools.chain(auth_events, state, [event])
        }

        create_event = None
        for e in auth_events:
            if (e.type, e.state_key) == (EventTypes.Create, ""):
                create_event = e
                break

        if create_event is None:
            # If the state doesn't have a create event then the room is
            # invalid, and it would fail auth checks anyway.
            raise SynapseError(400, "No create event in state")

        room_version_id = create_event.content.get(
            "room_version", RoomVersions.V1.identifier
        )

        if room_version.identifier != room_version_id:
            raise SynapseError(400, "Room version mismatch")

        missing_auth_events = set()
        for e in itertools.chain(auth_events, state, [event]):
            for e_id in e.auth_event_ids():
                if e_id not in event_map:
                    missing_auth_events.add(e_id)

        for e_id in missing_auth_events:
            m_ev = await self.federation_client.get_pdu(
                [origin], e_id, room_version=room_version, outlier=True, timeout=10000,
            )
            if m_ev and m_ev.event_id == e_id:
                event_map[e_id] = m_ev
            else:
                logger.info("Failed to find auth event %r", e_id)

        for e in itertools.chain(auth_events, state, [event]):
            auth_for_e = {
                (event_map[e_id].type, event_map[e_id].state_key): event_map[e_id]
                for e_id in e.auth_event_ids()
                if e_id in event_map
            }
            if create_event:
                auth_for_e[(EventTypes.Create, "")] = create_event

            try:
                event_auth.check(room_version, e, auth_events=auth_for_e)
            except SynapseError as err:
                # we may get SynapseErrors here as well as AuthErrors. For
                # instance, there are a couple of (ancient) events in some
                # rooms whose senders do not have the correct sigil; these
                # cause SynapseErrors in auth.check. We don't want to give up
                # the attempt to federate altogether in such cases.

                logger.warning("Rejecting %s because %s", e.event_id, err.msg)

                if e == event:
                    raise
                events_to_context[e.event_id].rejected = RejectedReason.AUTH_ERROR

        await self.persist_events_and_notify(
            [
                (e, events_to_context[e.event_id])
                for e in itertools.chain(auth_events, state)
            ]
        )

        new_event_context = await self.state_handler.compute_event_context(
            event, old_state=state
        )

        return await self.persist_events_and_notify([(event, new_event_context)])

    async def _prep_event(
        self,
        origin: str,
        event: EventBase,
        state: Optional[Iterable[EventBase]],
        auth_events: Optional[StateMap[EventBase]],
        backfilled: bool,
    ) -> EventContext:
        context = await self.state_handler.compute_event_context(event, old_state=state)

        if not auth_events:
            prev_state_ids = await context.get_prev_state_ids()
            auth_events_ids = await self.auth.compute_auth_events(
                event, prev_state_ids, for_verification=True
            )
            auth_events = await self.store.get_events(auth_events_ids)
            auth_events = {(e.type, e.state_key): e for e in auth_events.values()}

        # This is a hack to fix some old rooms where the initial join event
        # didn't reference the create event in its auth events.
        if event.type == EventTypes.Member and not event.auth_event_ids():
            if len(event.prev_event_ids()) == 1 and event.depth < 5:
                c = await self.store.get_event(
                    event.prev_event_ids()[0], allow_none=True
                )
                if c and c.type == EventTypes.Create:
                    auth_events[(c.type, c.state_key)] = c

        context = await self.do_auth(origin, event, context, auth_events=auth_events)

        if not context.rejected:
            await self._check_for_soft_fail(event, state, backfilled)

        if event.type == EventTypes.GuestAccess and not context.rejected:
            await self.maybe_kick_guest_users(event)

        return context

    async def _check_for_soft_fail(
        self, event: EventBase, state: Optional[Iterable[EventBase]], backfilled: bool
    ) -> None:
        """Checks if we should soft fail the event; if so, marks the event as
        such.

        Args:
            event
            state: The state at the event if we don't have all the event's prev events
            backfilled: Whether the event is from backfill
        """
        # For new (non-backfilled and non-outlier) events we check if the event
        # passes auth based on the current state. If it doesn't then we
        # "soft-fail" the event.
        do_soft_fail_check = not backfilled and not event.internal_metadata.is_outlier()
        if do_soft_fail_check:
            extrem_ids = await self.store.get_latest_event_ids_in_room(event.room_id)

            extrem_ids = set(extrem_ids)
            prev_event_ids = set(event.prev_event_ids())

            if extrem_ids == prev_event_ids:
                # If they're the same then the current state is the same as the
                # state at the event, so no point rechecking auth for soft fail.
                do_soft_fail_check = False

        if do_soft_fail_check:
            room_version = await self.store.get_room_version_id(event.room_id)
            room_version_obj = KNOWN_ROOM_VERSIONS[room_version]

            # Calculate the "current state".
            if state is not None:
                # If we're explicitly given the state then we won't have all the
                # prev events, and so we have a gap in the graph. In this case
                # we want to be a little careful as we might have been down for
                # a while and have an incorrect view of the current state,
                # however we still want to do checks as gaps are easy to
                # maliciously manufacture.
                #
                # So we use a "current state" that is actually a state
                # resolution across the current forward extremities and the
                # given state at the event. This should correctly handle cases
                # like bans, especially with state res v2.

                state_sets = await self.state_store.get_state_groups(
                    event.room_id, extrem_ids
                )
                state_sets = list(state_sets.values())
                state_sets.append(state)
                current_state_ids = await self.state_handler.resolve_events(
                    room_version, state_sets, event
                )
                current_state_ids = {
                    k: e.event_id for k, e in iteritems(current_state_ids)
                }
            else:
                current_state_ids = await self.state_handler.get_current_state_ids(
                    event.room_id, latest_event_ids=extrem_ids
                )

            logger.debug(
                "Doing soft-fail check for %s: state %s",
                event.event_id,
                current_state_ids,
            )

            # Now check if event pass auth against said current state
            auth_types = auth_types_for_event(event)
            current_state_ids = [
                e for k, e in iteritems(current_state_ids) if k in auth_types
            ]

            current_auth_events = await self.store.get_events(current_state_ids)
            current_auth_events = {
                (e.type, e.state_key): e for e in current_auth_events.values()
            }

            try:
                event_auth.check(
                    room_version_obj, event, auth_events=current_auth_events
                )
            except AuthError as e:
                logger.warning("Soft-failing %r because %s", event, e)
                event.internal_metadata.soft_failed = True

    async def on_query_auth(
        self, origin, event_id, room_id, remote_auth_chain, rejects, missing
    ):
        in_room = await self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        event = await self.store.get_event(
            event_id, allow_none=False, check_room_id=room_id
        )

        # Just go through and process each event in `remote_auth_chain`. We
        # don't want to fall into the trap of `missing` being wrong.
        for e in remote_auth_chain:
            try:
                await self._handle_new_event(origin, e)
            except AuthError:
                pass

        # Now get the current auth_chain for the event.
        local_auth_chain = await self.store.get_auth_chain(
            list(event.auth_event_ids()), include_given=True
        )

        # TODO: Check if we would now reject event_id. If so we need to tell
        # everyone.

        ret = await self.construct_auth_difference(local_auth_chain, remote_auth_chain)

        logger.debug("on_query_auth returning: %s", ret)

        return ret

    async def on_get_missing_events(
        self, origin, room_id, earliest_events, latest_events, limit
    ):
        in_room = await self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        # Only allow up to 20 events to be retrieved per request.
        limit = min(limit, 20)

        missing_events = await self.store.get_missing_events(
            room_id=room_id,
            earliest_events=earliest_events,
            latest_events=latest_events,
            limit=limit,
        )

        missing_events = await filter_events_for_server(
            self.storage, origin, missing_events
        )

        return missing_events

    async def do_auth(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        auth_events: StateMap[EventBase],
    ) -> EventContext:
        """

        Args:
            origin:
            event:
            context:
            auth_events:
                Map from (event_type, state_key) to event

                Normally, our calculated auth_events based on the state of the room
                at the event's position in the DAG, though occasionally (eg if the
                event is an outlier), may be the auth events claimed by the remote
                server.

                Also NB that this function adds entries to it.
        Returns:
            updated context object
        """
        room_version = await self.store.get_room_version_id(event.room_id)
        room_version_obj = KNOWN_ROOM_VERSIONS[room_version]

        try:
            context = await self._update_auth_events_and_context_for_auth(
                origin, event, context, auth_events
            )
        except Exception:
            # We don't really mind if the above fails, so lets not fail
            # processing if it does. However, it really shouldn't fail so
            # let's still log as an exception since we'll still want to fix
            # any bugs.
            logger.exception(
                "Failed to double check auth events for %s with remote. "
                "Ignoring failure and continuing processing of event.",
                event.event_id,
            )

        try:
            event_auth.check(room_version_obj, event, auth_events=auth_events)
        except AuthError as e:
            logger.warning("Failed auth resolution for %r because %s", event, e)
            context.rejected = RejectedReason.AUTH_ERROR

        return context

    async def _update_auth_events_and_context_for_auth(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        auth_events: StateMap[EventBase],
    ) -> EventContext:
        """Helper for do_auth. See there for docs.

        Checks whether a given event has the expected auth events. If it
        doesn't then we talk to the remote server to compare state to see if
        we can come to a consensus (e.g. if one server missed some valid
        state).

        This attempts to resolve any potential divergence of state between
        servers, but is not essential and so failures should not block further
        processing of the event.

        Args:
            origin:
            event:
            context:

            auth_events:
                Map from (event_type, state_key) to event

                Normally, our calculated auth_events based on the state of the room
                at the event's position in the DAG, though occasionally (eg if the
                event is an outlier), may be the auth events claimed by the remote
                server.

                Also NB that this function adds entries to it.

        Returns:
            updated context
        """
        event_auth_events = set(event.auth_event_ids())

        # missing_auth is the set of the event's auth_events which we don't yet have
        # in auth_events.
        missing_auth = event_auth_events.difference(
            e.event_id for e in auth_events.values()
        )

        # if we have missing events, we need to fetch those events from somewhere.
        #
        # we start by checking if they are in the store, and then try calling /event_auth/.
        if missing_auth:
            have_events = await self.store.have_seen_events(missing_auth)
            logger.debug("Events %s are in the store", have_events)
            missing_auth.difference_update(have_events)

        if missing_auth:
            # If we don't have all the auth events, we need to get them.
            logger.info("auth_events contains unknown events: %s", missing_auth)
            try:
                try:
                    remote_auth_chain = await self.federation_client.get_event_auth(
                        origin, event.room_id, event.event_id
                    )
                except RequestSendFailed as e:
                    # The other side isn't around or doesn't implement the
                    # endpoint, so lets just bail out.
                    logger.info("Failed to get event auth from remote: %s", e)
                    return context

                seen_remotes = await self.store.have_seen_events(
                    [e.event_id for e in remote_auth_chain]
                )

                for e in remote_auth_chain:
                    if e.event_id in seen_remotes:
                        continue

                    if e.event_id == event.event_id:
                        continue

                    try:
                        auth_ids = e.auth_event_ids()
                        auth = {
                            (e.type, e.state_key): e
                            for e in remote_auth_chain
                            if e.event_id in auth_ids or e.type == EventTypes.Create
                        }
                        e.internal_metadata.outlier = True

                        logger.debug(
                            "do_auth %s missing_auth: %s", event.event_id, e.event_id
                        )
                        await self._handle_new_event(origin, e, auth_events=auth)

                        if e.event_id in event_auth_events:
                            auth_events[(e.type, e.state_key)] = e
                    except AuthError:
                        pass

            except Exception:
                logger.exception("Failed to get auth chain")

        if event.internal_metadata.is_outlier():
            # XXX: given that, for an outlier, we'll be working with the
            # event's *claimed* auth events rather than those we calculated:
            # (a) is there any point in this test, since different_auth below will
            # obviously be empty
            # (b) alternatively, why don't we do it earlier?
            logger.info("Skipping auth_event fetch for outlier")
            return context

        different_auth = event_auth_events.difference(
            e.event_id for e in auth_events.values()
        )

        if not different_auth:
            return context

        logger.info(
            "auth_events refers to events which are not in our calculated auth "
            "chain: %s",
            different_auth,
        )

        # XXX: currently this checks for redactions but I'm not convinced that is
        # necessary?
        different_events = await self.store.get_events_as_list(different_auth)

        for d in different_events:
            if d.room_id != event.room_id:
                logger.warning(
                    "Event %s refers to auth_event %s which is in a different room",
                    event.event_id,
                    d.event_id,
                )

                # don't attempt to resolve the claimed auth events against our own
                # in this case: just use our own auth events.
                #
                # XXX: should we reject the event in this case? It feels like we should,
                # but then shouldn't we also do so if we've failed to fetch any of the
                # auth events?
                return context

        # now we state-resolve between our own idea of the auth events, and the remote's
        # idea of them.

        local_state = auth_events.values()
        remote_auth_events = dict(auth_events)
        remote_auth_events.update({(d.type, d.state_key): d for d in different_events})
        remote_state = remote_auth_events.values()

        room_version = await self.store.get_room_version_id(event.room_id)
        new_state = await self.state_handler.resolve_events(
            room_version, (local_state, remote_state), event
        )

        logger.info(
            "After state res: updating auth_events with new state %s",
            {
                (d.type, d.state_key): d.event_id
                for d in new_state.values()
                if auth_events.get((d.type, d.state_key)) != d
            },
        )

        auth_events.update(new_state)

        context = await self._update_context_for_auth_events(
            event, context, auth_events
        )

        return context

    async def _update_context_for_auth_events(
        self, event: EventBase, context: EventContext, auth_events: StateMap[EventBase]
    ) -> EventContext:
        """Update the state_ids in an event context after auth event resolution,
        storing the changes as a new state group.

        Args:
            event: The event we're handling the context for

            context: initial event context

            auth_events: Events to update in the event context.

        Returns:
            new event context
        """
        # exclude the state key of the new event from the current_state in the context.
        if event.is_state():
            event_key = (event.type, event.state_key)  # type: Optional[Tuple[str, str]]
        else:
            event_key = None
        state_updates = {
            k: a.event_id for k, a in iteritems(auth_events) if k != event_key
        }

        current_state_ids = await context.get_current_state_ids()
        current_state_ids = dict(current_state_ids)

        current_state_ids.update(state_updates)

        prev_state_ids = await context.get_prev_state_ids()
        prev_state_ids = dict(prev_state_ids)

        prev_state_ids.update({k: a.event_id for k, a in iteritems(auth_events)})

        # create a new state group as a delta from the existing one.
        prev_group = context.state_group
        state_group = await self.state_store.store_state_group(
            event.event_id,
            event.room_id,
            prev_group=prev_group,
            delta_ids=state_updates,
            current_state_ids=current_state_ids,
        )

        return EventContext.with_state(
            state_group=state_group,
            state_group_before_event=context.state_group_before_event,
            current_state_ids=current_state_ids,
            prev_state_ids=prev_state_ids,
            prev_group=prev_group,
            delta_ids=state_updates,
        )

    async def construct_auth_difference(
        self, local_auth: Iterable[EventBase], remote_auth: Iterable[EventBase]
    ) -> Dict:
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
                return next(it)
            except Exception:
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
            for e_id in e.auth_event_ids():
                if e_id in missing_remote_ids:
                    try:
                        base_remote_rejected.remove(e)
                    except ValueError:
                        pass

        reason_map = {}

        for e in base_remote_rejected:
            reason = await self.store.get_rejection_reason(e.event_id)
            if reason is None:
                # TODO: e is not in the current state, so we should
                # construct some proof of that.
                continue

            reason_map[e.event_id] = reason

        logger.debug("construct_auth_difference returning")

        return {
            "auth_chain": local_auth,
            "rejects": {
                e.event_id: {"reason": reason_map[e.event_id], "proof": None}
                for e in base_remote_rejected
            },
            "missing": [e.event_id for e in missing_locals],
        }

    @log_function
    async def exchange_third_party_invite(
        self, sender_user_id, target_user_id, room_id, signed
    ):
        third_party_invite = {"signed": signed}

        event_dict = {
            "type": EventTypes.Member,
            "content": {
                "membership": Membership.INVITE,
                "third_party_invite": third_party_invite,
            },
            "room_id": room_id,
            "sender": sender_user_id,
            "state_key": target_user_id,
        }

        if await self.auth.check_host_in_room(room_id, self.hs.hostname):
            room_version = await self.store.get_room_version_id(room_id)
            builder = self.event_builder_factory.new(room_version, event_dict)

            EventValidator().validate_builder(builder)
            event, context = await self.event_creation_handler.create_new_client_event(
                builder=builder
            )

            event_allowed = await self.third_party_event_rules.check_event_allowed(
                event, context
            )
            if not event_allowed:
                logger.info(
                    "Creation of threepid invite %s forbidden by third-party rules",
                    event,
                )
                raise SynapseError(
                    403, "This event is not allowed in this context", Codes.FORBIDDEN
                )

            event, context = await self.add_display_name_to_third_party_invite(
                room_version, event_dict, event, context
            )

            EventValidator().validate_new(event, self.config)

            # We need to tell the transaction queue to send this out, even
            # though the sender isn't a local user.
            event.internal_metadata.send_on_behalf_of = self.hs.hostname

            try:
                await self.auth.check_from_context(room_version, event, context)
            except AuthError as e:
                logger.warning("Denying new third party invite %r because %s", event, e)
                raise e

            await self._check_signature(event, context)

            # We retrieve the room member handler here as to not cause a cyclic dependency
            member_handler = self.hs.get_room_member_handler()
            await member_handler.send_membership_event(None, event, context)
        else:
            destinations = {x.split(":", 1)[-1] for x in (sender_user_id, room_id)}
            await self.federation_client.forward_third_party_invite(
                destinations, room_id, event_dict
            )

    async def on_exchange_third_party_invite_request(
        self, room_id: str, event_dict: JsonDict
    ) -> None:
        """Handle an exchange_third_party_invite request from a remote server

        The remote server will call this when it wants to turn a 3pid invite
        into a normal m.room.member invite.

        Args:
            room_id: The ID of the room.

            event_dict (dict[str, Any]): Dictionary containing the event body.

        """
        room_version = await self.store.get_room_version_id(room_id)

        # NB: event_dict has a particular specced format we might need to fudge
        # if we change event formats too much.
        builder = self.event_builder_factory.new(room_version, event_dict)

        event, context = await self.event_creation_handler.create_new_client_event(
            builder=builder
        )

        event_allowed = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not event_allowed:
            logger.warning(
                "Exchange of threepid invite %s forbidden by third-party rules", event
            )
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )

        event, context = await self.add_display_name_to_third_party_invite(
            room_version, event_dict, event, context
        )

        try:
            await self.auth.check_from_context(room_version, event, context)
        except AuthError as e:
            logger.warning("Denying third party invite %r because %s", event, e)
            raise e
        await self._check_signature(event, context)

        # We need to tell the transaction queue to send this out, even
        # though the sender isn't a local user.
        event.internal_metadata.send_on_behalf_of = get_domain_from_id(event.sender)

        # We retrieve the room member handler here as to not cause a cyclic dependency
        member_handler = self.hs.get_room_member_handler()
        await member_handler.send_membership_event(None, event, context)

    async def add_display_name_to_third_party_invite(
        self, room_version, event_dict, event, context
    ):
        key = (
            EventTypes.ThirdPartyInvite,
            event.content["third_party_invite"]["signed"]["token"],
        )
        original_invite = None
        prev_state_ids = await context.get_prev_state_ids()
        original_invite_id = prev_state_ids.get(key)
        if original_invite_id:
            original_invite = await self.store.get_event(
                original_invite_id, allow_none=True
            )
        if original_invite:
            # If the m.room.third_party_invite event's content is empty, it means the
            # invite has been revoked. In this case, we don't have to raise an error here
            # because the auth check will fail on the invite (because it's not able to
            # fetch public keys from the m.room.third_party_invite event's content, which
            # is empty).
            display_name = original_invite.content.get("display_name")
            event_dict["content"]["third_party_invite"]["display_name"] = display_name
        else:
            logger.info(
                "Could not find invite event for third_party_invite: %r", event_dict
            )
            # We don't discard here as this is not the appropriate place to do
            # auth checks. If we need the invite and don't have it then the
            # auth check code will explode appropriately.

        builder = self.event_builder_factory.new(room_version, event_dict)
        EventValidator().validate_builder(builder)
        event, context = await self.event_creation_handler.create_new_client_event(
            builder=builder
        )
        EventValidator().validate_new(event, self.config)
        return (event, context)

    async def _check_signature(self, event, context):
        """
        Checks that the signature in the event is consistent with its invite.

        Args:
            event (Event): The m.room.member event to check
            context (EventContext):

        Raises:
            AuthError: if signature didn't match any keys, or key has been
                revoked,
            SynapseError: if a transient error meant a key couldn't be checked
                for revocation.
        """
        signed = event.content["third_party_invite"]["signed"]
        token = signed["token"]

        prev_state_ids = await context.get_prev_state_ids()
        invite_event_id = prev_state_ids.get((EventTypes.ThirdPartyInvite, token))

        invite_event = None
        if invite_event_id:
            invite_event = await self.store.get_event(invite_event_id, allow_none=True)

        if not invite_event:
            raise AuthError(403, "Could not find invite")

        logger.debug("Checking auth on event %r", event.content)

        last_exception = None
        # for each public key in the 3pid invite event
        for public_key_object in self.hs.get_auth().get_public_keys(invite_event):
            try:
                # for each sig on the third_party_invite block of the actual invite
                for server, signature_block in signed["signatures"].items():
                    for key_name, encoded_signature in signature_block.items():
                        if not key_name.startswith("ed25519:"):
                            continue

                        logger.debug(
                            "Attempting to verify sig with key %s from %r "
                            "against pubkey %r",
                            key_name,
                            server,
                            public_key_object,
                        )

                        try:
                            public_key = public_key_object["public_key"]
                            verify_key = decode_verify_key_bytes(
                                key_name, decode_base64(public_key)
                            )
                            verify_signed_json(signed, server, verify_key)
                            logger.debug(
                                "Successfully verified sig with key %s from %r "
                                "against pubkey %r",
                                key_name,
                                server,
                                public_key_object,
                            )
                        except Exception:
                            logger.info(
                                "Failed to verify sig with key %s from %r "
                                "against pubkey %r",
                                key_name,
                                server,
                                public_key_object,
                            )
                            raise
                        try:
                            if "key_validity_url" in public_key_object:
                                await self._check_key_revocation(
                                    public_key, public_key_object["key_validity_url"]
                                )
                        except Exception:
                            logger.info(
                                "Failed to query key_validity_url %s",
                                public_key_object["key_validity_url"],
                            )
                            raise
                        return
            except Exception as e:
                last_exception = e
        raise last_exception

    async def _check_key_revocation(self, public_key, url):
        """
        Checks whether public_key has been revoked.

        Args:
            public_key (str): base-64 encoded public key.
            url (str): Key revocation URL.

        Raises:
            AuthError: if they key has been revoked.
            SynapseError: if a transient error meant a key couldn't be checked
                for revocation.
        """
        try:
            response = await self.http_client.get_json(url, {"public_key": public_key})
        except Exception:
            raise SynapseError(502, "Third party certificate could not be checked")
        if "valid" not in response or not response["valid"]:
            raise AuthError(403, "Third party certificate was invalid")

    async def persist_events_and_notify(
        self,
        event_and_contexts: Sequence[Tuple[EventBase, EventContext]],
        backfilled: bool = False,
    ) -> int:
        """Persists events and tells the notifier/pushers about them, if
        necessary.

        Args:
            event_and_contexts:
            backfilled: Whether these events are a result of
                backfilling or not
        """
        if self.config.worker.writers.events != self._instance_name:
            result = await self._send_events(
                instance_name=self.config.worker.writers.events,
                store=self.store,
                event_and_contexts=event_and_contexts,
                backfilled=backfilled,
            )
            return result["max_stream_id"]
        else:
            max_stream_id = await self.storage.persistence.persist_events(
                event_and_contexts, backfilled=backfilled
            )

            if self._ephemeral_messages_enabled:
                for (event, context) in event_and_contexts:
                    # If there's an expiry timestamp on the event, schedule its expiry.
                    self._message_handler.maybe_schedule_expiry(event)

            if not backfilled:  # Never notify for backfilled events
                for event, _ in event_and_contexts:
                    await self._notify_persisted_event(event, max_stream_id)

            return max_stream_id

    async def _notify_persisted_event(
        self, event: EventBase, max_stream_id: int
    ) -> None:
        """Checks to see if notifier/pushers should be notified about the
        event or not.

        Args:
            event:
            max_stream_id: The max_stream_id returned by persist_events
        """

        extra_users = []
        if event.type == EventTypes.Member:
            target_user_id = event.state_key

            # We notify for memberships if its an invite for one of our
            # users
            if event.internal_metadata.is_outlier():
                if event.membership != Membership.INVITE:
                    if not self.is_mine_id(target_user_id):
                        return

            target_user = UserID.from_string(target_user_id)
            extra_users.append(target_user)
        elif event.internal_metadata.is_outlier():
            return

        event_stream_id = event.internal_metadata.stream_ordering
        self.notifier.on_new_room_event(
            event, event_stream_id, max_stream_id, extra_users=extra_users
        )

        await self.pusher_pool.on_new_notifications(event_stream_id, max_stream_id)

    async def _clean_room_for_join(self, room_id: str) -> None:
        """Called to clean up any data in DB for a given room, ready for the
        server to join the room.

        Args:
            room_id
        """
        if self.config.worker_app:
            await self._clean_room_for_join_client(room_id)
        else:
            await self.store.clean_room_for_join(room_id)

    async def user_joined_room(self, user: UserID, room_id: str) -> None:
        """Called when a new user has joined the room
        """
        if self.config.worker_app:
            await self._notify_user_membership_change(
                room_id=room_id, user_id=user.to_string(), change="joined"
            )
        else:
            user_joined_room(self.distributor, user, room_id)

    async def get_room_complexity(self, remote_room_hosts, room_id):
        """
        Fetch the complexity of a remote room over federation.

        Args:
            remote_room_hosts (list[str]): The remote servers to ask.
            room_id (str): The room ID to ask about.

        Returns:
            Deferred[dict] or Deferred[None]: Dict contains the complexity
            metric versions, while None means we could not fetch the complexity.
        """

        for host in remote_room_hosts:
            res = await self.federation_client.get_room_complexity(host, room_id)

            # We got a result, return it.
            if res:
                return res

        # We fell off the bottom, couldn't get the complexity from anyone. Oh
        # well.
        return None
