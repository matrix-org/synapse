# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
# Copyright 2020 Sorunome
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
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Tuple, Union

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
    HttpResponseException,
    NotFoundError,
    RequestSendFailed,
    SynapseError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersion, RoomVersions
from synapse.crypto.event_signing import compute_event_signature
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.events.validator import EventValidator
from synapse.federation.federation_client import InvalidResponseError
from synapse.handlers._base import BaseHandler
from synapse.http.servlet import assert_params_in_dict
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    preserve_fn,
    run_in_background,
)
from synapse.logging.utils import log_function
from synapse.replication.http.federation import (
    ReplicationCleanRoomRestServlet,
    ReplicationStoreRoomOnOutlierMembershipRestServlet,
)
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.types import JsonDict, StateMap, get_domain_from_id
from synapse.util.async_helpers import Linearizer
from synapse.util.retryutils import NotRetryingDestination
from synapse.visibility import filter_events_for_server

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class FederationHandler(BaseHandler):
    """Handles general incoming federation requests

    Incoming events are *not* handled here, for which see FederationEventHandler.
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.hs = hs

        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state
        self.federation_client = hs.get_federation_client()
        self.state_handler = hs.get_state_handler()
        self.server_name = hs.hostname
        self.keyring = hs.get_keyring()
        self.is_mine_id = hs.is_mine_id
        self.spam_checker = hs.get_spam_checker()
        self.event_creation_handler = hs.get_event_creation_handler()
        self._event_auth_handler = hs.get_event_auth_handler()
        self._server_notices_mxid = hs.config.server_notices_mxid
        self.config = hs.config
        self.http_client = hs.get_proxied_blacklisted_http_client()
        self._replication = hs.get_replication_data_handler()
        self._federation_event_handler = hs.get_federation_event_handler()

        self._clean_room_for_join_client = ReplicationCleanRoomRestServlet.make_client(
            hs
        )

        if hs.config.worker_app:
            self._maybe_store_room_on_outlier_membership = (
                ReplicationStoreRoomOnOutlierMembershipRestServlet.make_client(hs)
            )
        else:
            self._maybe_store_room_on_outlier_membership = (
                self.store.maybe_store_room_on_outlier_membership
            )

        self._room_backfill = Linearizer("room_backfill")

        self.third_party_event_rules = hs.get_third_party_event_rules()

    async def maybe_backfill(
        self, room_id: str, current_depth: int, limit: int
    ) -> bool:
        """Checks the database to see if we should backfill before paginating,
        and if so do.

        Args:
            room_id
            current_depth: The depth from which we're paginating from. This is
                used to decide if we should backfill and what extremities to
                use.
            limit: The number of events that the pagination request will
                return. This is used as part of the heuristic to decide if we
                should back paginate.
        """
        with (await self._room_backfill.queue(room_id)):
            return await self._maybe_backfill_inner(room_id, current_depth, limit)

    async def _maybe_backfill_inner(
        self, room_id: str, current_depth: int, limit: int
    ) -> bool:
        oldest_events_with_depth = (
            await self.store.get_oldest_event_ids_with_depth_in_room(room_id)
        )
        insertion_events_to_be_backfilled = (
            await self.store.get_insertion_event_backwards_extremities_in_room(room_id)
        )
        logger.debug(
            "_maybe_backfill_inner: extremities oldest_events_with_depth=%s insertion_events_to_be_backfilled=%s",
            oldest_events_with_depth,
            insertion_events_to_be_backfilled,
        )

        if not oldest_events_with_depth and not insertion_events_to_be_backfilled:
            logger.debug("Not backfilling as no extremeties found.")
            return False

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

        forward_event_ids = await self.store.get_successor_events(
            list(oldest_events_with_depth)
        )

        extremities_events = await self.store.get_events(
            forward_event_ids,
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
        logger.debug(
            "_maybe_backfill_inner: filtered_extremities %s", filtered_extremities
        )

        if not filtered_extremities and not insertion_events_to_be_backfilled:
            return False

        extremities = {
            **oldest_events_with_depth,
            # TODO: insertion_events_to_be_backfilled is currently skipping the filtered_extremities checks
            **insertion_events_to_be_backfilled,
        }

        # Check if we reached a point where we should start backfilling.
        sorted_extremeties_tuple = sorted(extremities.items(), key=lambda e: -int(e[1]))
        max_depth = sorted_extremeties_tuple[0][1]

        # If we're approaching an extremity we trigger a backfill, otherwise we
        # no-op.
        #
        # We chose twice the limit here as then clients paginating backwards
        # will send pagination requests that trigger backfill at least twice
        # using the most recent extremity before it gets removed (see below). We
        # chose more than one times the limit in case of failure, but choosing a
        # much larger factor will result in triggering a backfill request much
        # earlier than necessary.
        if current_depth - 2 * limit > max_depth:
            logger.debug(
                "Not backfilling as we don't need to. %d < %d - 2 * %d",
                max_depth,
                current_depth,
                limit,
            )
            return False

        logger.debug(
            "room_id: %s, backfill: current_depth: %s, max_depth: %s, extrems: %s",
            room_id,
            current_depth,
            max_depth,
            sorted_extremeties_tuple,
        )

        # We ignore extremities that have a greater depth than our current depth
        # as:
        #    1. we don't really care about getting events that have happened
        #       before our current position; and
        #    2. we have likely previously tried and failed to backfill from that
        #       extremity, so to avoid getting "stuck" requesting the same
        #       backfill repeatedly we drop those extremities.
        filtered_sorted_extremeties_tuple = [
            t for t in sorted_extremeties_tuple if int(t[1]) <= current_depth
        ]

        # However, we need to check that the filtered extremities are non-empty.
        # If they are empty then either we can a) bail or b) still attempt to
        # backill. We opt to try backfilling anyway just in case we do get
        # relevant events.
        if filtered_sorted_extremeties_tuple:
            sorted_extremeties_tuple = filtered_sorted_extremeties_tuple

        # We don't want to specify too many extremities as it causes the backfill
        # request URI to be too long.
        extremities = dict(sorted_extremeties_tuple[:5])

        # Now we need to decide which hosts to hit first.

        # First we try hosts that are already in the room
        # TODO: HEURISTIC ALERT.

        curr_state = await self.state_handler.get_current_state(room_id)

        def get_domains_from_state(state: StateMap[EventBase]) -> List[Tuple[str, int]]:
            """Get joined domains from state

            Args:
                state: State map from type/state key to event.

            Returns:
                Returns a list of servers with the lowest depth of their joins.
                 Sorted by lowest depth first.
            """
            joined_users = [
                (state_key, int(event.depth))
                for (e_type, state_key), event in state.items()
                if e_type == EventTypes.Member and event.membership == Membership.JOIN
            ]

            joined_domains: Dict[str, int] = {}
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

        async def try_backfill(domains: List[str]) -> bool:
            # TODO: Should we try multiple of these at a time?
            for dom in domains:
                try:
                    await self._federation_event_handler.backfill(
                        dom, room_id, limit=100, extremities=extremities
                    )
                    # If this succeeded then we probably already have the
                    # appropriate stuff.
                    # TODO: We can probably do something more intelligent here.
                    return True
                except (SynapseError, InvalidResponseError) as e:
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
                    logger.info("Failed to get backfill from %s because %s", dom, e)
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
            [e_id for ids in states.values() for e_id in ids.values()],
            get_prev_content=False,
        )
        states = {
            key: {
                k: state_map[e_id]
                for k, e_id in state_dict.items()
                if e_id in state_map
            }
            for key, state_dict in states.items()
        }

        for e_id, _ in sorted_extremeties_tuple:
            likely_extremeties_domains = get_domains_from_state(states[e_id])

            success = await try_backfill(
                [
                    dom
                    for dom, _ in likely_extremeties_domains
                    if dom not in tried_domains
                ]
            )
            if success:
                return True

            tried_domains.update(dom for dom, _ in likely_extremeties_domains)

        return False

    async def send_invite(self, target_host: str, event: EventBase) -> EventBase:
        """Sends the invite to the remote server for signing.

        Invites must be signed by the invitee's server before distribution.
        """
        try:
            pdu = await self.federation_client.send_invite(
                destination=target_host,
                room_id=event.room_id,
                event_id=event.event_id,
                pdu=event,
            )
        except RequestSendFailed:
            raise SynapseError(502, f"Can't connect to server {target_host}")

        return pdu

    async def on_event_auth(self, event_id: str) -> List[EventBase]:
        event = await self.store.get_event(event_id)
        auth = await self.store.get_auth_chain(
            event.room_id, list(event.auth_event_ids()), include_given=True
        )
        return list(auth)

    async def do_invite_join(
        self, target_hosts: Iterable[str], room_id: str, joinee: str, content: JsonDict
    ) -> Tuple[str, int]:
        """Attempts to join the `joinee` to the room `room_id` via the
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
        assert room_id not in self._federation_event_handler.room_queues

        self._federation_event_handler.room_queues[room_id] = []

        await self._clean_room_for_join(room_id)

        try:
            # Try the host we successfully got a response to /make_join/
            # request first.
            host_list = list(target_hosts)
            try:
                host_list.remove(origin)
                host_list.insert(0, origin)
            except ValueError:
                pass

            ret = await self.federation_client.send_join(
                host_list, event, room_version_obj
            )

            event = ret.event
            origin = ret.origin
            state = ret.state
            auth_chain = ret.auth_chain
            auth_chain.sort(key=lambda e: e.depth)

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
                room_id=room_id,
                room_version=room_version_obj,
            )

            max_stream_id = await self._persist_auth_tree(
                origin, room_id, auth_chain, state, event, room_version_obj
            )

            # We wait here until this instance has seen the events come down
            # replication (if we're using replication) as the below uses caches.
            await self._replication.wait_for_stream_position(
                self.config.worker.events_shard_config.get_instance(room_id),
                "events",
                max_stream_id,
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
            room_queue = self._federation_event_handler.room_queues[room_id]
            del self._federation_event_handler.room_queues[room_id]

            # we don't need to wait for the queued events to be processed -
            # it's just a best-effort thing at this point. We do want to do
            # them roughly in order, though, otherwise we'll end up making
            # lots of requests for missing prev_events which we do actually
            # have. Hence we fire off the background task, but don't wait for it.

            run_in_background(self._handle_queued_pdus, room_queue)

    @log_function
    async def do_knock(
        self,
        target_hosts: List[str],
        room_id: str,
        knockee: str,
        content: JsonDict,
    ) -> Tuple[str, int]:
        """Sends the knock to the remote server.

        This first triggers a make_knock request that returns a partial
        event that we can fill out and sign. This is then sent to the
        remote server via send_knock.

        Knock events must be signed by the knockee's server before distributing.

        Args:
            target_hosts: A list of hosts that we want to try knocking through.
            room_id: The ID of the room to knock on.
            knockee: The ID of the user who is knocking.
            content: The content of the knock event.

        Returns:
            A tuple of (event ID, stream ID).

        Raises:
            SynapseError: If the chosen remote server returns a 3xx/4xx code.
            RuntimeError: If no servers were reachable.
        """
        logger.debug("Knocking on room %s on behalf of user %s", room_id, knockee)

        # Inform the remote server of the room versions we support
        supported_room_versions = list(KNOWN_ROOM_VERSIONS.keys())

        # Ask the remote server to create a valid knock event for us. Once received,
        # we sign the event
        params: Dict[str, Iterable[str]] = {"ver": supported_room_versions}
        origin, event, event_format_version = await self._make_and_verify_event(
            target_hosts, room_id, knockee, Membership.KNOCK, content, params=params
        )

        # Record the room ID and its version so that we have a record of the room
        await self._maybe_store_room_on_outlier_membership(
            room_id=event.room_id, room_version=event_format_version
        )

        # Initially try the host that we successfully called /make_knock on
        try:
            target_hosts.remove(origin)
            target_hosts.insert(0, origin)
        except ValueError:
            pass

        # Send the signed event back to the room, and potentially receive some
        # further information about the room in the form of partial state events
        stripped_room_state = await self.federation_client.send_knock(
            target_hosts, event
        )

        # Store any stripped room state events in the "unsigned" key of the event.
        # This is a bit of a hack and is cribbing off of invites. Basically we
        # store the room state here and retrieve it again when this event appears
        # in the invitee's sync stream. It is stripped out for all other local users.
        event.unsigned["knock_room_state"] = stripped_room_state["knock_state_events"]

        context = await self.state_handler.compute_event_context(event)
        stream_id = await self._federation_event_handler.persist_events_and_notify(
            event.room_id, [(event, context)]
        )
        return event.event_id, stream_id

    async def _handle_queued_pdus(
        self, room_queue: List[Tuple[EventBase, str]]
    ) -> None:
        """Process PDUs which got queued up while we were busy send_joining.

        Args:
            room_queue: list of PDUs to be processed and the servers that sent them
        """
        for p, origin in room_queue:
            try:
                logger.info(
                    "Processing queued PDU %s which was received while we were joining",
                    p,
                )
                with nested_logging_context(p.event_id):
                    await self._federation_event_handler.on_receive_pdu(origin, p)
            except Exception as e:
                logger.warning(
                    "Error handling queued PDU %s from %s: %s", p.event_id, origin, e
                )

    async def on_make_join_request(
        self, origin: str, room_id: str, user_id: str
    ) -> EventBase:
        """We've received a /make_join/ request, so we create a partial
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

        # checking the room version will check that we've actually heard of the room
        # (and return a 404 otherwise)
        room_version = await self.store.get_room_version(room_id)

        # now check that we are *still* in the room
        is_in_room = await self._event_auth_handler.check_host_in_room(
            room_id, self.server_name
        )
        if not is_in_room:
            logger.info(
                "Got /make_join request for room %s we are no longer in",
                room_id,
            )
            raise NotFoundError("Not an active room on this server")

        event_content = {"membership": Membership.JOIN}

        # If the current room is using restricted join rules, additional information
        # may need to be included in the event content in order to efficiently
        # validate the event.
        #
        # Note that this requires the /send_join request to come back to the
        # same server.
        if room_version.msc3083_join_rules:
            state_ids = await self.store.get_current_state_ids(room_id)
            if await self._event_auth_handler.has_restricted_join_rules(
                state_ids, room_version
            ):
                prev_member_event_id = state_ids.get((EventTypes.Member, user_id), None)
                # If the user is invited or joined to the room already, then
                # no additional info is needed.
                include_auth_user_id = True
                if prev_member_event_id:
                    prev_member_event = await self.store.get_event(prev_member_event_id)
                    include_auth_user_id = prev_member_event.membership not in (
                        Membership.JOIN,
                        Membership.INVITE,
                    )

                if include_auth_user_id:
                    event_content[
                        "join_authorised_via_users_server"
                    ] = await self._event_auth_handler.get_user_which_could_invite(
                        room_id,
                        state_ids,
                    )

        builder = self.event_builder_factory.new(
            room_version.identifier,
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
        except SynapseError as e:
            logger.warning("Failed to create join to %s because %s", room_id, e)
            raise

        # Ensure the user can even join the room.
        await self._federation_event_handler.check_join_restrictions(context, event)

        # The remote hasn't signed it yet, obviously. We'll do the full checks
        # when we get the event back in `on_send_join_request`
        await self._event_auth_handler.check_from_context(
            room_version.identifier, event, context, do_sig_check=False
        )

        return event

    async def on_invite_request(
        self, origin: str, event: EventBase, room_version: RoomVersion
    ) -> EventBase:
        """We've got an invite event. Process and persist it. Sign it.

        Respond with the now signed event.
        """
        if event.state_key is None:
            raise SynapseError(400, "The invite event did not have a state key")

        is_blocked = await self.store.is_room_blocked(event.room_id)
        if is_blocked:
            raise SynapseError(403, "This room has been blocked on this server")

        if self.hs.config.block_non_admin_invites:
            raise SynapseError(403, "This server does not accept room invites")

        if not await self.spam_checker.user_may_invite(
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
            raise SynapseError(HTTPStatus.FORBIDDEN, "Cannot invite this user")

        # We retrieve the room member handler here as to not cause a cyclic dependency
        member_handler = self.hs.get_room_member_handler()
        # We don't rate limit based on room ID, as that should be done by
        # sending server.
        await member_handler.ratelimit_invite(None, None, event.state_key)

        # keep a record of the room version, if we don't yet know it.
        # (this may get overwritten if we later get a different room version in a
        # join dance).
        await self._maybe_store_room_on_outlier_membership(
            room_id=event.room_id, room_version=room_version
        )

        event.internal_metadata.outlier = True
        event.internal_metadata.out_of_band_membership = True

        event.signatures.update(
            compute_event_signature(
                room_version,
                event.get_pdu_json(),
                self.hs.hostname,
                self.hs.signing_key,
            )
        )

        context = await self.state_handler.compute_event_context(event)
        await self._federation_event_handler.persist_events_and_notify(
            event.room_id, [(event, context)]
        )

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

        # Try the host that we successfully called /make_leave/ on first for
        # the /send_leave/ request.
        host_list = list(target_hosts)
        try:
            host_list.remove(origin)
            host_list.insert(0, origin)
        except ValueError:
            pass

        await self.federation_client.send_leave(host_list, event)

        context = await self.state_handler.compute_event_context(event)
        stream_id = await self._federation_event_handler.persist_events_and_notify(
            event.room_id, [(event, context)]
        )

        return event, stream_id

    async def _make_and_verify_event(
        self,
        target_hosts: Iterable[str],
        room_id: str,
        user_id: str,
        membership: str,
        content: JsonDict,
        params: Optional[Dict[str, Union[str, Iterable[str]]]] = None,
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
        """We've received a /make_leave/ request, so we create a partial
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

        try:
            # The remote hasn't signed it yet, obviously. We'll do the full checks
            # when we get the event back in `on_send_leave_request`
            await self._event_auth_handler.check_from_context(
                room_version, event, context, do_sig_check=False
            )
        except AuthError as e:
            logger.warning("Failed to create new leave %r because %s", event, e)
            raise e

        return event

    @log_function
    async def on_make_knock_request(
        self, origin: str, room_id: str, user_id: str
    ) -> EventBase:
        """We've received a make_knock request, so we create a partial
        knock event for the room and return that. We do *not* persist or
        process it until the other server has signed it and sent it back.

        Args:
            origin: The (verified) server name of the requesting server.
            room_id: The room to create the knock event in.
            user_id: The user to create the knock for.

        Returns:
            The partial knock event.
        """
        if get_domain_from_id(user_id) != origin:
            logger.info(
                "Get /make_knock request for user %r from different origin %s, ignoring",
                user_id,
                origin,
            )
            raise SynapseError(403, "User not from origin", Codes.FORBIDDEN)

        room_version = await self.store.get_room_version_id(room_id)

        builder = self.event_builder_factory.new(
            room_version,
            {
                "type": EventTypes.Member,
                "content": {"membership": Membership.KNOCK},
                "room_id": room_id,
                "sender": user_id,
                "state_key": user_id,
            },
        )

        event, context = await self.event_creation_handler.create_new_client_event(
            builder=builder
        )

        event_allowed, _ = await self.third_party_event_rules.check_event_allowed(
            event, context
        )
        if not event_allowed:
            logger.warning("Creation of knock %s forbidden by third-party rules", event)
            raise SynapseError(
                403, "This event is not allowed in this context", Codes.FORBIDDEN
            )

        try:
            # The remote hasn't signed it yet, obviously. We'll do the full checks
            # when we get the event back in `on_send_knock_request`
            await self._event_auth_handler.check_from_context(
                room_version, event, context, do_sig_check=False
            )
        except AuthError as e:
            logger.warning("Failed to create new knock %r because %s", event, e)
            raise e

        return event

    async def get_state_for_pdu(self, room_id: str, event_id: str) -> List[EventBase]:
        """Returns the state at the event. i.e. not including said event."""

        event = await self.store.get_event(event_id, check_room_id=room_id)

        state_groups = await self.state_store.get_state_groups(room_id, [event_id])

        if state_groups:
            _, state = list(state_groups.items()).pop()
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
        """Returns the state at the event. i.e. not including said event."""
        event = await self.store.get_event(event_id, check_room_id=room_id)

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
        in_room = await self._event_auth_handler.check_host_in_room(room_id, origin)
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
            in_room = await self._event_auth_handler.check_host_in_room(
                event.room_id, origin
            )
            if not in_room:
                raise AuthError(403, "Host not in room.")

            events = await filter_events_for_server(self.storage, origin, [event])
            event = events[0]
            return event
        else:
            return None

    async def _persist_auth_tree(
        self,
        origin: str,
        room_id: str,
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
            room_id,
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
                [origin],
                e_id,
                room_version=room_version,
                outlier=True,
                timeout=10000,
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

        if auth_events or state:
            await self._federation_event_handler.persist_events_and_notify(
                room_id,
                [
                    (e, events_to_context[e.event_id])
                    for e in itertools.chain(auth_events, state)
                ],
            )

        new_event_context = await self.state_handler.compute_event_context(
            event, old_state=state
        )

        return await self._federation_event_handler.persist_events_and_notify(
            room_id, [(event, new_event_context)]
        )

    async def on_get_missing_events(
        self,
        origin: str,
        room_id: str,
        earliest_events: List[str],
        latest_events: List[str],
        limit: int,
    ) -> List[EventBase]:
        in_room = await self._event_auth_handler.check_host_in_room(room_id, origin)
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

    async def construct_auth_difference(
        self, local_auth: Iterable[EventBase], remote_auth: Iterable[EventBase]
    ) -> Dict:
        """Given a local and remote auth chain, find the differences. This
        assumes that we have already processed all events in remote_auth

        Params:
            local_auth
            remote_auth

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
        self, sender_user_id: str, target_user_id: str, room_id: str, signed: JsonDict
    ) -> None:
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

        if await self._event_auth_handler.check_host_in_room(room_id, self.hs.hostname):
            room_version = await self.store.get_room_version_id(room_id)
            builder = self.event_builder_factory.new(room_version, event_dict)

            EventValidator().validate_builder(builder)
            event, context = await self.event_creation_handler.create_new_client_event(
                builder=builder
            )

            event, context = await self.add_display_name_to_third_party_invite(
                room_version, event_dict, event, context
            )

            EventValidator().validate_new(event, self.config)

            # We need to tell the transaction queue to send this out, even
            # though the sender isn't a local user.
            event.internal_metadata.send_on_behalf_of = self.hs.hostname

            try:
                await self._event_auth_handler.check_from_context(
                    room_version, event, context
                )
            except AuthError as e:
                logger.warning("Denying new third party invite %r because %s", event, e)
                raise e

            await self._check_signature(event, context)

            # We retrieve the room member handler here as to not cause a cyclic dependency
            member_handler = self.hs.get_room_member_handler()
            await member_handler.send_membership_event(None, event, context)
        else:
            destinations = {x.split(":", 1)[-1] for x in (sender_user_id, room_id)}

            try:
                await self.federation_client.forward_third_party_invite(
                    destinations, room_id, event_dict
                )
            except (RequestSendFailed, HttpResponseException):
                raise SynapseError(502, "Failed to forward third party invite")

    async def on_exchange_third_party_invite_request(
        self, event_dict: JsonDict
    ) -> None:
        """Handle an exchange_third_party_invite request from a remote server

        The remote server will call this when it wants to turn a 3pid invite
        into a normal m.room.member invite.

        Args:
            event_dict: Dictionary containing the event body.

        """
        assert_params_in_dict(event_dict, ["room_id"])
        room_version = await self.store.get_room_version_id(event_dict["room_id"])

        # NB: event_dict has a particular specced format we might need to fudge
        # if we change event formats too much.
        builder = self.event_builder_factory.new(room_version, event_dict)

        event, context = await self.event_creation_handler.create_new_client_event(
            builder=builder
        )
        event, context = await self.add_display_name_to_third_party_invite(
            room_version, event_dict, event, context
        )

        try:
            await self._event_auth_handler.check_from_context(
                room_version, event, context
            )
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
        self,
        room_version: str,
        event_dict: JsonDict,
        event: EventBase,
        context: EventContext,
    ) -> Tuple[EventBase, EventContext]:
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

    async def _check_signature(self, event: EventBase, context: EventContext) -> None:
        """
        Checks that the signature in the event is consistent with its invite.

        Args:
            event: The m.room.member event to check
            context:

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

        last_exception: Optional[Exception] = None

        # for each public key in the 3pid invite event
        for public_key_object in event_auth.get_public_keys(invite_event):
            try:
                # for each sig on the third_party_invite block of the actual invite
                for server, signature_block in signed["signatures"].items():
                    for key_name in signature_block.keys():
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

        if last_exception is None:
            # we can only get here if get_public_keys() returned an empty list
            # TODO: make this better
            raise RuntimeError("no public key in invite event")

        raise last_exception

    async def _check_key_revocation(self, public_key: str, url: str) -> None:
        """
        Checks whether public_key has been revoked.

        Args:
            public_key: base-64 encoded public key.
            url: Key revocation URL.

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

    async def get_room_complexity(
        self, remote_room_hosts: List[str], room_id: str
    ) -> Optional[dict]:
        """
        Fetch the complexity of a remote room over federation.

        Args:
            remote_room_hosts (list[str]): The remote servers to ask.
            room_id (str): The room ID to ask about.

        Returns:
            Dict contains the complexity
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
