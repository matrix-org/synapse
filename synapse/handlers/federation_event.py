# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import (
    TYPE_CHECKING,
    Collection,
    Container,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import attr
from prometheus_client import Counter

from twisted.internet import defer

from synapse import event_auth
from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    Membership,
    RejectedReason,
    RoomEncryptionAlgorithms,
)
from synapse.api.errors import (
    AuthError,
    Codes,
    FederationError,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.event_auth import auth_types_for_event
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.federation.federation_client import InvalidResponseError
from synapse.handlers._base import BaseHandler
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    run_in_background,
)
from synapse.logging.utils import log_function
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.http.devices import ReplicationUserDevicesResyncRestServlet
from synapse.replication.http.federation import (
    ReplicationFederationSendEventsRestServlet,
)
from synapse.state import StateResolutionStore
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.types import (
    MutableStateMap,
    PersistedEventPosition,
    RoomStreamToken,
    StateMap,
    UserID,
    get_domain_from_id,
)
from synapse.util.async_helpers import Linearizer, concurrently_execute
from synapse.util.iterutils import batch_iter
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import shortstr

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)

soft_failed_event_counter = Counter(
    "synapse_federation_soft_failed_events_total",
    "Events received over federation that we marked as soft_failed",
)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _NewEventInfo:
    """Holds information about a received event, ready for passing to _auth_and_persist_events

    Attributes:
        event: the received event

        claimed_auth_event_map: a map of (type, state_key) => event for the event's
            claimed auth_events.

            This can include events which have not yet been persisted, in the case that
            we are backfilling a batch of events.

            Note: May be incomplete: if we were unable to find all of the claimed auth
            events. Also, treat the contents with caution: the events might also have
            been rejected, might not yet have been authorized themselves, or they might
            be in the wrong room.

    """

    event: EventBase
    claimed_auth_event_map: StateMap[EventBase]


class FederationEventHandler(BaseHandler):
    """Handles events that originated from federation.

    Responsible for handing incoming events and passing them on to the rest
    of the homeserver (including auth and state conflict resolutions)
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state

        self.state_handler = hs.get_state_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self._event_auth_handler = hs.get_event_auth_handler()
        self._message_handler = hs.get_message_handler()
        self.action_generator = hs.get_action_generator()
        self._state_resolution_handler = hs.get_state_resolution_handler()

        self.federation_client = hs.get_federation_client()
        self.third_party_event_rules = hs.get_third_party_event_rules()

        self.is_mine_id = hs.is_mine_id
        self._instance_name = hs.get_instance_name()

        self.config = hs.config
        self._ephemeral_messages_enabled = hs.config.server.enable_ephemeral_messages

        self._send_events = ReplicationFederationSendEventsRestServlet.make_client(hs)
        if hs.config.worker_app:
            self._user_device_resync = (
                ReplicationUserDevicesResyncRestServlet.make_client(hs)
            )
        else:
            self._device_list_updater = hs.get_device_handler().device_list_updater

        # When joining a room we need to queue any events for that room up.
        # For each room, a list of (pdu, origin) tuples.
        # TODO: replace this with something more elegant, probably based around the
        # federation event staging area.
        self.room_queues: Dict[str, List[Tuple[EventBase, str]]] = {}

        self._room_pdu_linearizer = Linearizer("fed_room_pdu")

    async def on_receive_pdu(self, origin: str, pdu: EventBase) -> None:
        """Process a PDU received via a federation /send/ transaction

        Args:
            origin: server which initiated the /send/ transaction. Will
                be used to fetch missing events or state.
            pdu: received PDU
        """

        room_id = pdu.room_id
        event_id = pdu.event_id

        # We reprocess pdus when we have seen them only as outliers
        existing = await self.store.get_event(
            event_id, allow_none=True, allow_rejected=True
        )

        # FIXME: Currently we fetch an event again when we already have it
        # if it has been marked as an outlier.
        if existing:
            if not existing.internal_metadata.is_outlier():
                logger.info(
                    "Ignoring received event %s which we have already seen", event_id
                )
                return
            if pdu.internal_metadata.is_outlier():
                logger.info(
                    "Ignoring received outlier %s which we already have as an outlier",
                    event_id,
                )
                return
            logger.info("De-outliering event %s", event_id)

        # do some initial sanity-checking of the event. In particular, make
        # sure it doesn't have hundreds of prev_events or auth_events, which
        # could cause a huge state resolution or cascade of event fetches.
        try:
            self._sanity_check_event(pdu)
        except SynapseError as err:
            logger.warning("Received event failed sanity checks")
            raise FederationError("ERROR", err.code, err.msg, affected=pdu.event_id)

        # If we are currently in the process of joining this room, then we
        # queue up events for later processing.
        if room_id in self.room_queues:
            logger.info(
                "Queuing PDU from %s for now: join in progress",
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
        is_in_room = await self._event_auth_handler.check_host_in_room(
            room_id, self.server_name
        )
        if not is_in_room:
            logger.info(
                "Ignoring PDU from %s as we're not in the room",
                origin,
            )
            return None

        # Check that the event passes auth based on the state at the event. This is
        # done for events that are to be added to the timeline (non-outliers).
        #
        # Get missing pdus if necessary:
        #  - Fetching any missing prev events to fill in gaps in the graph
        #  - Fetching state if we have a hole in the graph
        if not pdu.internal_metadata.is_outlier():
            prevs = set(pdu.prev_event_ids())
            seen = await self.store.have_events_in_timeline(prevs)
            missing_prevs = prevs - seen

            if missing_prevs:
                # We only backfill backwards to the min depth.
                min_depth = await self.get_min_depth_for_context(pdu.room_id)
                logger.debug("min_depth: %d", min_depth)

                if min_depth is not None and pdu.depth > min_depth:
                    # If we're missing stuff, ensure we only fetch stuff one
                    # at a time.
                    logger.info(
                        "Acquiring room lock to fetch %d missing prev_events: %s",
                        len(missing_prevs),
                        shortstr(missing_prevs),
                    )
                    with (await self._room_pdu_linearizer.queue(pdu.room_id)):
                        logger.info(
                            "Acquired room lock to fetch %d missing prev_events",
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
                            ) from e

                    # Update the set of things we've seen after trying to
                    # fetch the missing stuff
                    seen = await self.store.have_events_in_timeline(prevs)
                    missing_prevs = prevs - seen

                    if not missing_prevs:
                        logger.info("Found all missing prev_events")

                if missing_prevs:
                    # since this event was pushed to us, it is possible for it to
                    # become the only forward-extremity in the room, and we would then
                    # trust its state to be the state for the whole room. This is very
                    # bad. Further, if the event was pushed to us, there is no excuse
                    # for us not to have all the prev_events. (XXX: apart from
                    # min_depth?)
                    #
                    # We therefore reject any such events.
                    logger.warning(
                        "Rejecting: failed to fetch %d prev events: %s",
                        len(missing_prevs),
                        shortstr(missing_prevs),
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

        await self._process_received_pdu(origin, pdu, state=None)

    @log_function
    async def on_send_membership_event(
        self, origin: str, event: EventBase
    ) -> Tuple[EventBase, EventContext]:
        """
        We have received a join/leave/knock event for a room via send_join/leave/knock.

        Verify that event and send it into the room on the remote homeserver's behalf.

        This is quite similar to on_receive_pdu, with the following principal
        differences:
          * only membership events are permitted (and only events with
            sender==state_key -- ie, no kicks or bans)
          * *We* send out the event on behalf of the remote server.
          * We enforce the membership restrictions of restricted rooms.
          * Rejected events result in an exception rather than being stored.

        There are also other differences, however it is not clear if these are by
        design or omission. In particular, we do not attempt to backfill any missing
        prev_events.

        Args:
            origin: The homeserver of the remote (joining/invited/knocking) user.
            event: The member event that has been signed by the remote homeserver.

        Returns:
            The event and context of the event after inserting it into the room graph.

        Raises:
            SynapseError if the event is not accepted into the room
        """
        logger.debug(
            "on_send_membership_event: Got event: %s, signatures: %s",
            event.event_id,
            event.signatures,
        )

        if get_domain_from_id(event.sender) != origin:
            logger.info(
                "Got send_membership request for user %r from different origin %s",
                event.sender,
                origin,
            )
            raise SynapseError(403, "User not from origin", Codes.FORBIDDEN)

        if event.sender != event.state_key:
            raise SynapseError(400, "state_key and sender must match", Codes.BAD_JSON)

        assert not event.internal_metadata.outlier

        # Send this event on behalf of the other server.
        #
        # The remote server isn't a full participant in the room at this point, so
        # may not have an up-to-date list of the other homeservers participating in
        # the room, so we send it on their behalf.
        event.internal_metadata.send_on_behalf_of = origin

        context = await self.state_handler.compute_event_context(event)
        context = await self._check_event_auth(origin, event, context)
        if context.rejected:
            raise SynapseError(
                403, f"{event.membership} event was rejected", Codes.FORBIDDEN
            )

        # for joins, we need to check the restrictions of restricted rooms
        if event.membership == Membership.JOIN:
            await self.check_join_restrictions(context, event)

        # for knock events, we run the third-party event rules. It's not entirely clear
        # why we don't do this for other sorts of membership events.
        if event.membership == Membership.KNOCK:
            event_allowed, _ = await self.third_party_event_rules.check_event_allowed(
                event, context
            )
            if not event_allowed:
                logger.info("Sending of knock %s forbidden by third-party rules", event)
                raise SynapseError(
                    403, "This event is not allowed in this context", Codes.FORBIDDEN
                )

        # all looks good, we can persist the event.
        await self._run_push_actions_and_persist_event(event, context)
        return event, context

    async def check_join_restrictions(
        self, context: EventContext, event: EventBase
    ) -> None:
        """Check that restrictions in restricted join rules are matched

        Called when we receive a join event via send_join.

        Raises an auth error if the restrictions are not matched.
        """
        prev_state_ids = await context.get_prev_state_ids()

        # Check if the user is already in the room or invited to the room.
        user_id = event.state_key
        prev_member_event_id = prev_state_ids.get((EventTypes.Member, user_id), None)
        prev_member_event = None
        if prev_member_event_id:
            prev_member_event = await self.store.get_event(prev_member_event_id)

        # Check if the member should be allowed access via membership in a space.
        await self._event_auth_handler.check_restricted_join_rules(
            prev_state_ids,
            event.room_version,
            user_id,
            prev_member_event,
        )

    @log_function
    async def backfill(
        self, dest: str, room_id: str, limit: int, extremities: List[str]
    ) -> None:
        """Trigger a backfill request to `dest` for the given `room_id`

        This will attempt to get more events from the remote. If the other side
        has no new events to offer, this will return an empty list.

        As the events are received, we check their signatures, and also do some
        sanity-checking on them. If any of the backfilled events are invalid,
        this method throws a SynapseError.

        We might also raise an InvalidResponseError if the response from the remote
        server is just bogus.

        TODO: make this more useful to distinguish failures of the remote
        server from invalid events (there is probably no point in trying to
        re-fetch invalid events from every other HS in the room.)
        """
        if dest == self.server_name:
            raise SynapseError(400, "Can't backfill from self.")

        events = await self.federation_client.backfill(
            dest, room_id, limit=limit, extremities=extremities
        )

        if not events:
            return

        # if there are any events in the wrong room, the remote server is buggy and
        # should not be trusted.
        for ev in events:
            if ev.room_id != room_id:
                raise InvalidResponseError(
                    f"Remote server {dest} returned event {ev.event_id} which is in "
                    f"room {ev.room_id}, when we were backfilling in {room_id}"
                )

        await self._process_pulled_events(dest, events, backfilled=True)

    async def _get_missing_events_for_pdu(
        self, origin: str, pdu: EventBase, prevs: Set[str], min_depth: int
    ) -> None:
        """
        Args:
            origin: Origin of the pdu. Will be called to get the missing events
            pdu: received pdu
            prevs: List of event ids which we are missing
            min_depth: Minimum depth of events to return.
        """

        room_id = pdu.room_id
        event_id = pdu.event_id

        seen = await self.store.have_events_in_timeline(prevs)

        if not prevs - seen:
            return

        latest_list = await self.store.get_latest_event_ids_in_room(room_id)

        # We add the prev events that we have seen to the latest
        # list to ensure the remote server doesn't give them to us
        latest = set(latest_list)
        latest |= seen

        logger.info(
            "Requesting missing events between %s and %s",
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
        # request out aggressively on the client side:
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
        # - the aggressive 10s timeout was introduced to deal with incoming federation
        #   requests taking 8 hours to process. It's not entirely clear why that was going
        #   on; certainly there were other issues causing traffic storms which are now
        #   resolved, and I think in any case we may be more sensible about our locking
        #   now. We're *certainly* more sensible about our logging.
        #
        # All that said: Let's try increasing the timeout to 60s and see what happens.

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
            logger.warning("Failed to get prev_events: %s", e)
            return

        logger.info("Got %d prev_events", len(missing_events))
        await self._process_pulled_events(origin, missing_events, backfilled=False)

    async def _process_pulled_events(
        self, origin: str, events: Iterable[EventBase], backfilled: bool
    ) -> None:
        """Process a batch of events we have pulled from a remote server

        Pulls in any events required to auth the events, persists the received events,
        and notifies clients, if appropriate.

        Assumes the events have already had their signatures and hashes checked.

        Params:
            origin: The server we received these events from
            events: The received events.
            backfilled: True if this is part of a historical batch of events (inhibits
                notification to clients, and validation of device keys.)
        """

        # We want to sort these by depth so we process them and
        # tell clients about them in order.
        sorted_events = sorted(events, key=lambda x: x.depth)

        for ev in sorted_events:
            with nested_logging_context(ev.event_id):
                await self._process_pulled_event(origin, ev, backfilled=backfilled)

    async def _process_pulled_event(
        self, origin: str, event: EventBase, backfilled: bool
    ) -> None:
        """Process a single event that we have pulled from a remote server

        Pulls in any events required to auth the event, persists the received event,
        and notifies clients, if appropriate.

        Assumes the event has already had its signatures and hashes checked.

        This is somewhat equivalent to on_receive_pdu, but applies somewhat different
        logic in the case that we are missing prev_events (in particular, it just
        requests the state at that point, rather than triggering a get_missing_events) -
        so is appropriate when we have pulled the event from a remote server, rather
        than having it pushed to us.

        Params:
            origin: The server we received this event from
            events: The received event
            backfilled: True if this is part of a historical batch of events (inhibits
                notification to clients, and validation of device keys.)
        """
        logger.info("Processing pulled event %s", event)

        # these should not be outliers.
        assert not event.internal_metadata.is_outlier()

        event_id = event.event_id

        existing = await self.store.get_event(
            event_id, allow_none=True, allow_rejected=True
        )
        if existing:
            if not existing.internal_metadata.is_outlier():
                logger.info(
                    "Ignoring received event %s which we have already seen",
                    event_id,
                )
                return
            logger.info("De-outliering event %s", event_id)

        try:
            self._sanity_check_event(event)
        except SynapseError as err:
            logger.warning("Event %s failed sanity check: %s", event_id, err)
            return

        try:
            state = await self._resolve_state_at_missing_prevs(origin, event)
            await self._process_received_pdu(
                origin, event, state=state, backfilled=backfilled
            )
        except FederationError as e:
            if e.code == 403:
                logger.warning("Pulled event %s failed history check.", event_id)
            else:
                raise

    async def _resolve_state_at_missing_prevs(
        self, dest: str, event: EventBase
    ) -> Optional[Iterable[EventBase]]:
        """Calculate the state at an event with missing prev_events.

        This is used when we have pulled a batch of events from a remote server, and
        still don't have all the prev_events.

        If we already have all the prev_events for `event`, this method does nothing.

        Otherwise, the missing prevs become new backwards extremities, and we fall back
        to asking the remote server for the state after each missing `prev_event`,
        and resolving across them.

        That's ok provided we then resolve the state against other bits of the DAG
        before using it - in other words, that the received event `event` is not going
        to become the only forwards_extremity in the room (which will ensure that you
        can't just take over a room by sending an event, withholding its prev_events,
        and declaring yourself to be an admin in the subsequent state request).

        In other words: we should only call this method if `event` has been *pulled*
        as part of a batch of missing prev events, or similar.

        Params:
            dest: the remote server to ask for state at the missing prevs. Typically,
                this will be the server we got `event` from.
            event: an event to check for missing prevs.

        Returns:
            if we already had all the prev events, `None`. Otherwise, returns a list of
            the events in the state at `event`.
        """
        room_id = event.room_id
        event_id = event.event_id

        prevs = set(event.prev_event_ids())
        seen = await self.store.have_events_in_timeline(prevs)
        missing_prevs = prevs - seen

        if not missing_prevs:
            return None

        logger.info(
            "Event %s is missing prev_events %s: calculating state for a "
            "backwards extremity",
            event_id,
            shortstr(missing_prevs),
        )
        # Calculate the state after each of the previous events, and
        # resolve them to find the correct state at the current event.
        event_map = {event_id: event}
        try:
            # Get the state of the events we know about
            ours = await self.state_store.get_state_groups_ids(room_id, seen)

            # state_maps is a list of mappings from (type, state_key) to event_id
            state_maps: List[StateMap[str]] = list(ours.values())

            # we don't need this any more, let's delete it.
            del ours

            # Ask the remote server for the states we don't
            # know about
            for p in missing_prevs:
                logger.info("Requesting state after missing prev_event %s", p)

                with nested_logging_context(p):
                    # note that if any of the missing prevs share missing state or
                    # auth events, the requests to fetch those events are deduped
                    # by the get_pdu_cache in federation_client.
                    remote_state = await self._get_state_after_missing_prev_event(
                        dest, room_id, p
                    )

                    remote_state_map = {
                        (x.type, x.state_key): x.event_id for x in remote_state
                    }
                    state_maps.append(remote_state_map)

                    for x in remote_state:
                        event_map[x.event_id] = x

            room_version = await self.store.get_room_version_id(room_id)
            state_map = await self._state_resolution_handler.resolve_events_with_store(
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

            state = [event_map[e] for e in state_map.values()]
        except Exception:
            logger.warning(
                "Error attempting to resolve state at missing prev_events",
                exc_info=True,
            )
            raise FederationError(
                "ERROR",
                403,
                "We can't get valid state history.",
                affected=event_id,
            )
        return state

    async def _get_state_after_missing_prev_event(
        self,
        destination: str,
        room_id: str,
        event_id: str,
    ) -> List[EventBase]:
        """Requests all of the room state at a given event from a remote homeserver.

        Args:
            destination: The remote homeserver to query for the state.
            room_id: The id of the room we're interested in.
            event_id: The id of the event we want the state at.

        Returns:
            A list of events in the state, including the event itself
        """
        (
            state_event_ids,
            auth_event_ids,
        ) = await self.federation_client.get_room_state_ids(
            destination, room_id, event_id=event_id
        )

        logger.debug(
            "state_ids returned %i state events, %i auth events",
            len(state_event_ids),
            len(auth_event_ids),
        )

        # start by just trying to fetch the events from the store
        desired_events = set(state_event_ids)
        desired_events.add(event_id)
        logger.debug("Fetching %i events from cache/store", len(desired_events))
        fetched_events = await self.store.get_events(
            desired_events, allow_rejected=True
        )

        missing_desired_events = desired_events - fetched_events.keys()
        logger.debug(
            "We are missing %i events (got %i)",
            len(missing_desired_events),
            len(fetched_events),
        )

        # We probably won't need most of the auth events, so let's just check which
        # we have for now, rather than thrashing the event cache with them all
        # unnecessarily.

        # TODO: we probably won't actually need all of the auth events, since we
        #   already have a bunch of the state events. It would be nice if the
        #   federation api gave us a way of finding out which we actually need.

        missing_auth_events = set(auth_event_ids) - fetched_events.keys()
        missing_auth_events.difference_update(
            await self.store.have_seen_events(room_id, missing_auth_events)
        )
        logger.debug("We are also missing %i auth events", len(missing_auth_events))

        missing_events = missing_desired_events | missing_auth_events
        logger.debug("Fetching %i events from remote", len(missing_events))
        await self._get_events_and_persist(
            destination=destination, room_id=room_id, events=missing_events
        )

        # we need to make sure we re-load from the database to get the rejected
        # state correct.
        fetched_events.update(
            await self.store.get_events(missing_desired_events, allow_rejected=True)
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
            # bad events from the returned state set.
            logger.warning(
                "Remote server %s claims event %s in room %s is an auth/state "
                "event in room %s",
                destination,
                bad_event_id,
                bad_room_id,
                room_id,
            )

            del fetched_events[bad_event_id]

        # if we couldn't get the prev event in question, that's a problem.
        remote_event = fetched_events.get(event_id)
        if not remote_event:
            raise Exception("Unable to get missing prev_event %s" % (event_id,))

        # missing state at that event is a warning, not a blocker
        # XXX: this doesn't sound right? it means that we'll end up with incomplete
        #   state.
        failed_to_fetch = desired_events - fetched_events.keys()
        if failed_to_fetch:
            logger.warning(
                "Failed to fetch missing state events for %s %s",
                event_id,
                failed_to_fetch,
            )

        remote_state = [
            fetched_events[e_id] for e_id in state_event_ids if e_id in fetched_events
        ]

        if remote_event.is_state() and remote_event.rejected_reason is None:
            remote_state.append(remote_event)

        return remote_state

    async def _process_received_pdu(
        self,
        origin: str,
        event: EventBase,
        state: Optional[Iterable[EventBase]],
        backfilled: bool = False,
    ) -> None:
        """Called when we have a new pdu. We need to do auth checks and put it
        through the StateHandler.

        Args:
            origin: server sending the event

            event: event to be persisted

            state: Normally None, but if we are handling a gap in the graph
                (ie, we are missing one or more prev_events), the resolved state at the
                event

            backfilled: True if this is part of a historical batch of events (inhibits
                notification to clients, and validation of device keys.)
        """
        logger.debug("Processing event: %s", event)

        try:
            context = await self.state_handler.compute_event_context(
                event, old_state=state
            )
            await self._auth_and_persist_event(
                origin, event, context, state=state, backfilled=backfilled
            )
        except AuthError as e:
            raise FederationError("ERROR", e.code, e.msg, affected=event.event_id)

        if backfilled:
            return

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

                current_keys: Container[str] = []

                if device:
                    keys = device.get("keys", {}).get("keys", {})

                    if (
                        event.content.get("algorithm")
                        == RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2
                    ):
                        # For this algorithm we expect a curve25519 key.
                        key_name = "curve25519:%s" % (device_id,)
                        current_keys = [keys.get(key_name)]
                    else:
                        # We don't know understand the algorithm, so we just
                        # check it matches a key for the device.
                        current_keys = keys.values()
                elif device_id:
                    # We don't have any keys for the device ID.
                    pass
                else:
                    # The event didn't include a device ID, so we just look for
                    # keys across all devices.
                    current_keys = [
                        key
                        for device in cached_devices.values()
                        for key in device.get("keys", {}).get("keys", {}).values()
                    ]

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
                run_as_background_process(
                    "resync_device_due_to_pdu",
                    self._resync_device,
                    event.sender,
                )

        await self._handle_marker_event(origin, event)

    async def _resync_device(self, sender: str) -> None:
        """We have detected that the device list for the given user may be out
        of sync, so we try and resync them.
        """

        try:
            await self.store.mark_remote_user_device_cache_as_stale(sender)

            # Immediately attempt a resync in the background
            if self.config.worker_app:
                await self._user_device_resync(user_id=sender)
            else:
                await self._device_list_updater.user_device_resync(sender)
        except Exception:
            logger.exception("Failed to resync device for %s", sender)

    async def _handle_marker_event(self, origin: str, marker_event: EventBase):
        """Handles backfilling the insertion event when we receive a marker
        event that points to one.

        Args:
            origin: Origin of the event. Will be called to get the insertion event
            marker_event: The event to process
        """

        if marker_event.type != EventTypes.MSC2716_MARKER:
            # Not a marker event
            return

        if marker_event.rejected_reason is not None:
            # Rejected event
            return

        # Skip processing a marker event if the room version doesn't
        # support it.
        room_version = await self.store.get_room_version(marker_event.room_id)
        if not room_version.msc2716_historical:
            return

        logger.debug("_handle_marker_event: received %s", marker_event)

        insertion_event_id = marker_event.content.get(
            EventContentFields.MSC2716_MARKER_INSERTION
        )

        if insertion_event_id is None:
            # Nothing to retrieve then (invalid marker)
            return

        logger.debug(
            "_handle_marker_event: backfilling insertion event %s", insertion_event_id
        )

        await self._get_events_and_persist(
            origin,
            marker_event.room_id,
            [insertion_event_id],
        )

        insertion_event = await self.store.get_event(
            insertion_event_id, allow_none=True
        )
        if insertion_event is None:
            logger.warning(
                "_handle_marker_event: server %s didn't return insertion event %s for marker %s",
                origin,
                insertion_event_id,
                marker_event.event_id,
            )
            return

        logger.debug(
            "_handle_marker_event: succesfully backfilled insertion event %s from marker event %s",
            insertion_event,
            marker_event,
        )

        await self.store.insert_insertion_extremity(
            insertion_event_id, marker_event.room_id
        )

        logger.debug(
            "_handle_marker_event: insertion extremity added for %s from marker event %s",
            insertion_event,
            marker_event,
        )

    async def _get_events_and_persist(
        self, destination: str, room_id: str, events: Iterable[str]
    ) -> None:
        """Fetch the given events from a server, and persist them as outliers.

        This function *does not* recursively get missing auth events of the
        newly fetched events. Callers must include in the `events` argument
        any missing events from the auth chain.

        Logs a warning if we can't find the given event.
        """

        room_version = await self.store.get_room_version(room_id)

        event_map: Dict[str, EventBase] = {}

        async def get_event(event_id: str):
            with nested_logging_context(event_id):
                try:
                    event = await self.federation_client.get_pdu(
                        [destination],
                        event_id,
                        room_version,
                        outlier=True,
                    )
                    if event is None:
                        logger.warning(
                            "Server %s didn't return event %s",
                            destination,
                            event_id,
                        )
                        return

                    event_map[event.event_id] = event

                except Exception as e:
                    logger.warning(
                        "Error fetching missing state/auth event %s: %s %s",
                        event_id,
                        type(e),
                        e,
                    )

        await concurrently_execute(get_event, events, 5)

        # Make a map of auth events for each event. We do this after fetching
        # all the events as some of the events' auth events will be in the list
        # of requested events.

        auth_events = [
            aid
            for event in event_map.values()
            for aid in event.auth_event_ids()
            if aid not in event_map
        ]
        persisted_events = await self.store.get_events(
            auth_events,
            allow_rejected=True,
        )

        event_infos = []
        for event in event_map.values():
            auth = {}
            for auth_event_id in event.auth_event_ids():
                ae = persisted_events.get(auth_event_id) or event_map.get(auth_event_id)
                if ae:
                    auth[(ae.type, ae.state_key)] = ae
                else:
                    logger.info("Missing auth event %s", auth_event_id)

            event_infos.append(_NewEventInfo(event, auth))

        if event_infos:
            await self._auth_and_persist_events(
                destination,
                room_id,
                event_infos,
            )

    async def _auth_and_persist_events(
        self,
        origin: str,
        room_id: str,
        event_infos: Collection[_NewEventInfo],
    ) -> None:
        """Creates the appropriate contexts and persists events. The events
        should not depend on one another, e.g. this should be used to persist
        a bunch of outliers, but not a chunk of individual events that depend
        on each other for state calculations.

        Notifies about the events where appropriate.
        """

        if not event_infos:
            return

        async def prep(ev_info: _NewEventInfo):
            event = ev_info.event
            with nested_logging_context(suffix=event.event_id):
                res = await self.state_handler.compute_event_context(event)
                res = await self._check_event_auth(
                    origin,
                    event,
                    res,
                    claimed_auth_event_map=ev_info.claimed_auth_event_map,
                )
            return res

        contexts = await make_deferred_yieldable(
            defer.gatherResults(
                [run_in_background(prep, ev_info) for ev_info in event_infos],
                consumeErrors=True,
            )
        )

        await self.persist_events_and_notify(
            room_id,
            [
                (ev_info.event, context)
                for ev_info, context in zip(event_infos, contexts)
            ],
        )

    async def _auth_and_persist_event(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        state: Optional[Iterable[EventBase]] = None,
        claimed_auth_event_map: Optional[StateMap[EventBase]] = None,
        backfilled: bool = False,
    ) -> None:
        """
        Process an event by performing auth checks and then persisting to the database.

        Args:
            origin: The host the event originates from.
            event: The event itself.
            context:
                The event context.

            state:
                The state events used to check the event for soft-fail. If this is
                not provided the current state events will be used.

            claimed_auth_event_map:
                A map of (type, state_key) => event for the event's claimed auth_events.
                Possibly incomplete, and possibly including events that are not yet
                persisted, or authed, or in the right room.

                Only populated where we may not already have persisted these events -
                for example, when populating outliers.

            backfilled: True if the event was backfilled.
        """
        context = await self._check_event_auth(
            origin,
            event,
            context,
            state=state,
            claimed_auth_event_map=claimed_auth_event_map,
            backfilled=backfilled,
        )

        await self._run_push_actions_and_persist_event(event, context, backfilled)

    async def _check_event_auth(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        state: Optional[Iterable[EventBase]] = None,
        claimed_auth_event_map: Optional[StateMap[EventBase]] = None,
        backfilled: bool = False,
    ) -> EventContext:
        """
        Checks whether an event should be rejected (for failing auth checks).

        Args:
            origin: The host the event originates from.
            event: The event itself.
            context:
                The event context.

            state:
                The state events used to check the event for soft-fail. If this is
                not provided the current state events will be used.

            claimed_auth_event_map:
                A map of (type, state_key) => event for the event's claimed auth_events.
                Possibly incomplete, and possibly including events that are not yet
                persisted, or authed, or in the right room.

                Only populated where we may not already have persisted these events -
                for example, when populating outliers, or the state for a backwards
                extremity.

            backfilled: True if the event was backfilled.

        Returns:
            The updated context object.
        """
        room_version = await self.store.get_room_version_id(event.room_id)
        room_version_obj = KNOWN_ROOM_VERSIONS[room_version]

        if claimed_auth_event_map:
            # if we have a copy of the auth events from the event, use that as the
            # basis for auth.
            auth_events = claimed_auth_event_map
        else:
            # otherwise, we calculate what the auth events *should* be, and use that
            prev_state_ids = await context.get_prev_state_ids()
            auth_events_ids = self._event_auth_handler.compute_auth_events(
                event, prev_state_ids, for_verification=True
            )
            auth_events_x = await self.store.get_events(auth_events_ids)
            auth_events = {(e.type, e.state_key): e for e in auth_events_x.values()}

        try:
            (
                context,
                auth_events_for_auth,
            ) = await self._update_auth_events_and_context_for_auth(
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
            auth_events_for_auth = auth_events

        try:
            event_auth.check(room_version_obj, event, auth_events=auth_events_for_auth)
        except AuthError as e:
            logger.warning("Failed auth resolution for %r because %s", event, e)
            context.rejected = RejectedReason.AUTH_ERROR

        if not context.rejected:
            await self._check_for_soft_fail(event, state, backfilled, origin=origin)

        if event.type == EventTypes.GuestAccess and not context.rejected:
            await self.maybe_kick_guest_users(event)

        # If we are going to send this event over federation we precaclculate
        # the joined hosts.
        if event.internal_metadata.get_send_on_behalf_of():
            await self.event_creation_handler.cache_joined_hosts_for_event(
                event, context
            )

        return context

    async def _check_for_soft_fail(
        self,
        event: EventBase,
        state: Optional[Iterable[EventBase]],
        backfilled: bool,
        origin: str,
    ) -> None:
        """Checks if we should soft fail the event; if so, marks the event as
        such.

        Args:
            event
            state: The state at the event if we don't have all the event's prev events
            backfilled: Whether the event is from backfill
            origin: The host the event originates from.
        """
        # For new (non-backfilled and non-outlier) events we check if the event
        # passes auth based on the current state. If it doesn't then we
        # "soft-fail" the event.
        if backfilled or event.internal_metadata.is_outlier():
            return

        extrem_ids_list = await self.store.get_latest_event_ids_in_room(event.room_id)
        extrem_ids = set(extrem_ids_list)
        prev_event_ids = set(event.prev_event_ids())

        if extrem_ids == prev_event_ids:
            # If they're the same then the current state is the same as the
            # state at the event, so no point rechecking auth for soft fail.
            return

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

            state_sets_d = await self.state_store.get_state_groups(
                event.room_id, extrem_ids
            )
            state_sets: List[Iterable[EventBase]] = list(state_sets_d.values())
            state_sets.append(state)
            current_states = await self.state_handler.resolve_events(
                room_version, state_sets, event
            )
            current_state_ids: StateMap[str] = {
                k: e.event_id for k, e in current_states.items()
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
        auth_types = auth_types_for_event(room_version_obj, event)
        current_state_ids_list = [
            e for k, e in current_state_ids.items() if k in auth_types
        ]

        auth_events_map = await self.store.get_events(current_state_ids_list)
        current_auth_events = {
            (e.type, e.state_key): e for e in auth_events_map.values()
        }

        try:
            event_auth.check(room_version_obj, event, auth_events=current_auth_events)
        except AuthError as e:
            logger.warning(
                "Soft-failing %r (from %s) because %s",
                event,
                e,
                origin,
                extra={
                    "room_id": event.room_id,
                    "mxid": event.sender,
                    "hs": origin,
                },
            )
            soft_failed_event_counter.inc()
            event.internal_metadata.soft_failed = True

    async def _update_auth_events_and_context_for_auth(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        input_auth_events: StateMap[EventBase],
    ) -> Tuple[EventContext, StateMap[EventBase]]:
        """Helper for _check_event_auth. See there for docs.

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

            input_auth_events:
                Map from (event_type, state_key) to event

                Normally, our calculated auth_events based on the state of the room
                at the event's position in the DAG, though occasionally (eg if the
                event is an outlier), may be the auth events claimed by the remote
                server.

        Returns:
            updated context, updated auth event map
        """
        # take a copy of input_auth_events before we modify it.
        auth_events: MutableStateMap[EventBase] = dict(input_auth_events)

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
            have_events = await self.store.have_seen_events(event.room_id, missing_auth)
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
                except RequestSendFailed as e1:
                    # The other side isn't around or doesn't implement the
                    # endpoint, so lets just bail out.
                    logger.info("Failed to get event auth from remote: %s", e1)
                    return context, auth_events

                seen_remotes = await self.store.have_seen_events(
                    event.room_id, [e.event_id for e in remote_auth_chain]
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
                            "_check_event_auth %s missing_auth: %s",
                            event.event_id,
                            e.event_id,
                        )
                        missing_auth_event_context = (
                            await self.state_handler.compute_event_context(e)
                        )
                        await self._auth_and_persist_event(
                            origin,
                            e,
                            missing_auth_event_context,
                            claimed_auth_event_map=auth,
                        )

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
            return context, auth_events

        different_auth = event_auth_events.difference(
            e.event_id for e in auth_events.values()
        )

        if not different_auth:
            return context, auth_events

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
                return context, auth_events

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

        return context, auth_events

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
            event_key: Optional[Tuple[str, str]] = (event.type, event.state_key)
        else:
            event_key = None
        state_updates = {
            k: a.event_id for k, a in auth_events.items() if k != event_key
        }

        current_state_ids = await context.get_current_state_ids()
        current_state_ids = dict(current_state_ids)  # type: ignore

        current_state_ids.update(state_updates)

        prev_state_ids = await context.get_prev_state_ids()
        prev_state_ids = dict(prev_state_ids)

        prev_state_ids.update({k: a.event_id for k, a in auth_events.items()})

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

    async def _run_push_actions_and_persist_event(
        self, event: EventBase, context: EventContext, backfilled: bool = False
    ):
        """Run the push actions for a received event, and persist it.

        Args:
            event: The event itself.
            context: The event context.
            backfilled: True if the event was backfilled.
        """
        try:
            if (
                not event.internal_metadata.is_outlier()
                and not backfilled
                and not context.rejected
                and (await self.store.get_min_depth(event.room_id)) <= event.depth
            ):
                await self.action_generator.handle_push_actions_for_event(
                    event, context
                )

            await self.persist_events_and_notify(
                event.room_id, [(event, context)], backfilled=backfilled
            )
        except Exception:
            run_in_background(
                self.store.remove_push_actions_from_staging, event.event_id
            )
            raise

    async def persist_events_and_notify(
        self,
        room_id: str,
        event_and_contexts: Sequence[Tuple[EventBase, EventContext]],
        backfilled: bool = False,
    ) -> int:
        """Persists events and tells the notifier/pushers about them, if
        necessary.

        Args:
            room_id: The room ID of events being persisted.
            event_and_contexts: Sequence of events with their associated
                context that should be persisted. All events must belong to
                the same room.
            backfilled: Whether these events are a result of
                backfilling or not

        Returns:
            The stream ID after which all events have been persisted.
        """
        if not event_and_contexts:
            return self.store.get_current_events_token()

        instance = self.config.worker.events_shard_config.get_instance(room_id)
        if instance != self._instance_name:
            # Limit the number of events sent over replication. We choose 200
            # here as that is what we default to in `max_request_body_size(..)`
            for batch in batch_iter(event_and_contexts, 200):
                result = await self._send_events(
                    instance_name=instance,
                    store=self.store,
                    room_id=room_id,
                    event_and_contexts=batch,
                    backfilled=backfilled,
                )
            return result["max_stream_id"]
        else:
            assert self.storage.persistence

            # Note that this returns the events that were persisted, which may not be
            # the same as were passed in if some were deduplicated due to transaction IDs.
            events, max_stream_token = await self.storage.persistence.persist_events(
                event_and_contexts, backfilled=backfilled
            )

            if self._ephemeral_messages_enabled:
                for event in events:
                    # If there's an expiry timestamp on the event, schedule its expiry.
                    self._message_handler.maybe_schedule_expiry(event)

            if not backfilled:  # Never notify for backfilled events
                for event in events:
                    await self._notify_persisted_event(event, max_stream_token)

            return max_stream_token.stream

    async def _notify_persisted_event(
        self, event: EventBase, max_stream_token: RoomStreamToken
    ) -> None:
        """Checks to see if notifier/pushers should be notified about the
        event or not.

        Args:
            event:
            max_stream_token: The max_stream_id returned by persist_events
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

        # the event has been persisted so it should have a stream ordering.
        assert event.internal_metadata.stream_ordering

        event_pos = PersistedEventPosition(
            self._instance_name, event.internal_metadata.stream_ordering
        )
        self.notifier.on_new_room_event(
            event, event_pos, max_stream_token, extra_users=extra_users
        )

    def _sanity_check_event(self, ev: EventBase) -> None:
        """
        Do some early sanity checks of a received event

        In particular, checks it doesn't have an excessive number of
        prev_events or auth_events, which could cause a huge state resolution
        or cascade of event fetches.

        Args:
            ev: event to be checked

        Raises:
            SynapseError if the event does not pass muster
        """
        if len(ev.prev_event_ids()) > 20:
            logger.warning(
                "Rejecting event %s which has %i prev_events",
                ev.event_id,
                len(ev.prev_event_ids()),
            )
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Too many prev_events")

        if len(ev.auth_event_ids()) > 10:
            logger.warning(
                "Rejecting event %s which has %i auth_events",
                ev.event_id,
                len(ev.auth_event_ids()),
            )
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Too many auth_events")

    async def get_min_depth_for_context(self, context: str) -> int:
        return await self.store.get_min_depth(context)
