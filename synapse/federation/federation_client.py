# Copyright 2015-2022 The Matrix.org Foundation C.I.C.
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


import copy
import itertools
import logging
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Collection,
    Container,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

import attr
from prometheus_client import Counter

from synapse.api.constants import EventContentFields, EventTypes, Membership
from synapse.api.errors import (
    CodeMessageException,
    Codes,
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
    UnsupportedRoomVersionError,
)
from synapse.api.room_versions import (
    KNOWN_ROOM_VERSIONS,
    EventFormatVersions,
    RoomVersion,
    RoomVersions,
)
from synapse.events import EventBase, builder
from synapse.federation.federation_base import (
    FederationBase,
    InvalidEventSignatureError,
    event_from_pdu_json,
)
from synapse.federation.transport.client import SendJoinResponse
from synapse.http.types import QueryParams
from synapse.types import JsonDict, UserID, get_domain_from_id
from synapse.util.async_helpers import concurrently_execute
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.retryutils import NotRetryingDestination

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

sent_queries_counter = Counter("synapse_federation_client_sent_queries", "", ["type"])


PDU_RETRY_TIME_MS = 1 * 60 * 1000

T = TypeVar("T")


class InvalidResponseError(RuntimeError):
    """Helper for _try_destination_list: indicates that the server returned a response
    we couldn't parse
    """


@attr.s(slots=True, frozen=True, auto_attribs=True)
class SendJoinResult:
    # The event to persist.
    event: EventBase
    # A string giving the server the event was sent to.
    origin: str
    state: List[EventBase]
    auth_chain: List[EventBase]

    # True if 'state' elides non-critical membership events
    partial_state: bool

    # if 'partial_state' is set, a list of the servers in the room (otherwise empty)
    servers_in_room: List[str]


class FederationClient(FederationBase):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.pdu_destination_tried: Dict[str, Dict[str, int]] = {}
        self._clock.looping_call(self._clear_tried_cache, 60 * 1000)
        self.state = hs.get_state_handler()
        self.transport_layer = hs.get_federation_transport_client()

        self.hostname = hs.hostname
        self.signing_key = hs.signing_key

        self._get_pdu_cache: ExpiringCache[str, EventBase] = ExpiringCache(
            cache_name="get_pdu_cache",
            clock=self._clock,
            max_len=1000,
            expiry_ms=120 * 1000,
            reset_expiry_on_get=False,
        )

        # A cache for fetching the room hierarchy over federation.
        #
        # Some stale data over federation is OK, but must be refreshed
        # periodically since the local server is in the room.
        #
        # It is a map of (room ID, suggested-only) -> the response of
        # get_room_hierarchy.
        self._get_room_hierarchy_cache: ExpiringCache[
            Tuple[str, bool],
            Tuple[JsonDict, Sequence[JsonDict], Sequence[JsonDict], Sequence[str]],
        ] = ExpiringCache(
            cache_name="get_room_hierarchy_cache",
            clock=self._clock,
            max_len=1000,
            expiry_ms=5 * 60 * 1000,
            reset_expiry_on_get=False,
        )

    def _clear_tried_cache(self) -> None:
        """Clear pdu_destination_tried cache"""
        now = self._clock.time_msec()

        old_dict = self.pdu_destination_tried
        self.pdu_destination_tried = {}

        for event_id, destination_dict in old_dict.items():
            destination_dict = {
                dest: time
                for dest, time in destination_dict.items()
                if time + PDU_RETRY_TIME_MS > now
            }
            if destination_dict:
                self.pdu_destination_tried[event_id] = destination_dict

    async def make_query(
        self,
        destination: str,
        query_type: str,
        args: QueryParams,
        retry_on_dns_fail: bool = False,
        ignore_backoff: bool = False,
    ) -> JsonDict:
        """Sends a federation Query to a remote homeserver of the given type
        and arguments.

        Args:
            destination: Domain name of the remote homeserver
            query_type: Category of the query type; should match the
                handler name used in register_query_handler().
            args: Mapping of strings to strings containing the details
                of the query request.
            ignore_backoff: true to ignore the historical backoff data
                and try the request anyway.

        Returns:
            The JSON object from the response
        """
        sent_queries_counter.labels(query_type).inc()

        return await self.transport_layer.make_query(
            destination,
            query_type,
            args,
            retry_on_dns_fail=retry_on_dns_fail,
            ignore_backoff=ignore_backoff,
        )

    async def query_client_keys(
        self, destination: str, content: JsonDict, timeout: int
    ) -> JsonDict:
        """Query device keys for a device hosted on a remote server.

        Args:
            destination: Domain name of the remote homeserver
            content: The query content.

        Returns:
            The JSON object from the response
        """
        sent_queries_counter.labels("client_device_keys").inc()
        return await self.transport_layer.query_client_keys(
            destination, content, timeout
        )

    async def query_user_devices(
        self, destination: str, user_id: str, timeout: int = 30000
    ) -> JsonDict:
        """Query the device keys for a list of user ids hosted on a remote
        server.
        """
        sent_queries_counter.labels("user_devices").inc()
        return await self.transport_layer.query_user_devices(
            destination, user_id, timeout
        )

    async def claim_client_keys(
        self, destination: str, content: JsonDict, timeout: int
    ) -> JsonDict:
        """Claims one-time keys for a device hosted on a remote server.

        Args:
            destination: Domain name of the remote homeserver
            content: The query content.

        Returns:
            The JSON object from the response
        """
        sent_queries_counter.labels("client_one_time_keys").inc()
        return await self.transport_layer.claim_client_keys(
            destination, content, timeout
        )

    async def backfill(
        self, dest: str, room_id: str, limit: int, extremities: Collection[str]
    ) -> Optional[List[EventBase]]:
        """Requests some more historic PDUs for the given room from the
        given destination server.

        Args:
            dest: The remote homeserver to ask.
            room_id: The room_id to backfill.
            limit: The maximum number of events to return.
            extremities: our current backwards extremities, to backfill from
                Must be a Collection that is falsy when empty.
                (Iterable is not enough here!)
        """
        logger.debug("backfill extrem=%s", extremities)

        # If there are no extremities then we've (probably) reached the start.
        if not extremities:
            return None

        transaction_data = await self.transport_layer.backfill(
            dest, room_id, extremities, limit
        )

        logger.debug("backfill transaction_data=%r", transaction_data)

        if not isinstance(transaction_data, dict):
            # TODO we probably want an exception type specific to federation
            # client validation.
            raise TypeError("Backfill transaction_data is not a dict.")

        transaction_data_pdus = transaction_data.get("pdus")
        if not isinstance(transaction_data_pdus, list):
            # TODO we probably want an exception type specific to federation
            # client validation.
            raise TypeError("transaction_data.pdus is not a list.")

        room_version = await self.store.get_room_version(room_id)

        pdus = [event_from_pdu_json(p, room_version) for p in transaction_data_pdus]

        # Check signatures and hash of pdus, removing any from the list that fail checks
        pdus[:] = await self._check_sigs_and_hash_and_fetch(
            dest, pdus, room_version=room_version
        )

        return pdus

    async def get_pdu_from_destination_raw(
        self,
        destination: str,
        event_id: str,
        room_version: RoomVersion,
        timeout: Optional[int] = None,
    ) -> Optional[EventBase]:
        """Requests the PDU with given origin and ID from the remote home
        server. Does not have any caching or rate limiting!

        Args:
            destination: Which homeserver to query
            event_id: event to fetch
            room_version: version of the room
            timeout: How long to try (in ms) each destination for before
                moving to the next destination. None indicates no timeout.

        Returns:
            The requested PDU, or None if we were unable to find it.

        Raises:
            SynapseError, NotRetryingDestination, FederationDeniedError
        """
        transaction_data = await self.transport_layer.get_event(
            destination, event_id, timeout=timeout
        )

        logger.debug(
            "retrieved event id %s from %s: %r",
            event_id,
            destination,
            transaction_data,
        )

        pdu_list: List[EventBase] = [
            event_from_pdu_json(p, room_version) for p in transaction_data["pdus"]
        ]

        if pdu_list and pdu_list[0]:
            pdu = pdu_list[0]

            # Check signatures are correct.
            try:
                signed_pdu = await self._check_sigs_and_hash(room_version, pdu)
            except InvalidEventSignatureError as e:
                errmsg = f"event id {pdu.event_id}: {e}"
                logger.warning("%s", errmsg)
                raise SynapseError(403, errmsg, Codes.FORBIDDEN)

            return signed_pdu

        return None

    async def get_pdu(
        self,
        destinations: Iterable[str],
        event_id: str,
        room_version: RoomVersion,
        timeout: Optional[int] = None,
    ) -> Optional[EventBase]:
        """Requests the PDU with given origin and ID from the remote home
        servers.

        Will attempt to get the PDU from each destination in the list until
        one succeeds.

        Args:
            destinations: Which homeservers to query
            event_id: event to fetch
            room_version: version of the room
            timeout: How long to try (in ms) each destination for before
                moving to the next destination. None indicates no timeout.

        Returns:
            The requested PDU, or None if we were unable to find it.
        """

        # TODO: Rate limit the number of times we try and get the same event.

        ev = self._get_pdu_cache.get(event_id)
        if ev:
            return ev

        pdu_attempts = self.pdu_destination_tried.setdefault(event_id, {})

        signed_pdu = None
        for destination in destinations:
            now = self._clock.time_msec()
            last_attempt = pdu_attempts.get(destination, 0)
            if last_attempt + PDU_RETRY_TIME_MS > now:
                continue

            try:
                signed_pdu = await self.get_pdu_from_destination_raw(
                    destination=destination,
                    event_id=event_id,
                    room_version=room_version,
                    timeout=timeout,
                )

                pdu_attempts[destination] = now

            except SynapseError as e:
                logger.info(
                    "Failed to get PDU %s from %s because %s", event_id, destination, e
                )
                continue
            except NotRetryingDestination as e:
                logger.info(str(e))
                continue
            except FederationDeniedError as e:
                logger.info(str(e))
                continue
            except Exception as e:
                pdu_attempts[destination] = now

                logger.info(
                    "Failed to get PDU %s from %s because %s", event_id, destination, e
                )
                continue

        if signed_pdu:
            self._get_pdu_cache[event_id] = signed_pdu

        return signed_pdu

    async def get_room_state_ids(
        self, destination: str, room_id: str, event_id: str
    ) -> Tuple[List[str], List[str]]:
        """Calls the /state_ids endpoint to fetch the state at a particular point
        in the room, and the auth events for the given event

        Returns:
            a tuple of (state event_ids, auth event_ids)

        Raises:
            InvalidResponseError: if fields in the response have the wrong type.
        """
        result = await self.transport_layer.get_room_state_ids(
            destination, room_id, event_id=event_id
        )

        state_event_ids = result["pdu_ids"]
        auth_event_ids = result.get("auth_chain_ids", [])

        if not isinstance(state_event_ids, list) or not isinstance(
            auth_event_ids, list
        ):
            raise InvalidResponseError("invalid response from /state_ids")

        return state_event_ids, auth_event_ids

    async def get_room_state(
        self,
        destination: str,
        room_id: str,
        event_id: str,
        room_version: RoomVersion,
    ) -> Tuple[List[EventBase], List[EventBase]]:
        """Calls the /state endpoint to fetch the state at a particular point
        in the room.

        Any invalid events (those with incorrect or unverifiable signatures or hashes)
        are filtered out from the response, and any duplicate events are removed.

        (Size limits and other event-format checks are *not* performed.)

        Note that the result is not ordered, so callers must be careful to process
        the events in an order that handles dependencies.

        Returns:
            a tuple of (state events, auth events)
        """
        result = await self.transport_layer.get_room_state(
            room_version,
            destination,
            room_id,
            event_id,
        )
        state_events = result.state
        auth_events = result.auth_events

        # we may as well filter out any duplicates from the response, to save
        # processing them multiple times. (In particular, events may be present in
        # `auth_events` as well as `state`, which is redundant).
        #
        # We don't rely on the sort order of the events, so we can just stick them
        # in a dict.
        state_event_map = {event.event_id: event for event in state_events}
        auth_event_map = {
            event.event_id: event
            for event in auth_events
            if event.event_id not in state_event_map
        }

        logger.info(
            "Processing from /state: %d state events, %d auth events",
            len(state_event_map),
            len(auth_event_map),
        )

        valid_auth_events = await self._check_sigs_and_hash_and_fetch(
            destination, auth_event_map.values(), room_version
        )

        valid_state_events = await self._check_sigs_and_hash_and_fetch(
            destination, state_event_map.values(), room_version
        )

        return valid_state_events, valid_auth_events

    async def _check_sigs_and_hash_and_fetch(
        self,
        origin: str,
        pdus: Collection[EventBase],
        room_version: RoomVersion,
    ) -> List[EventBase]:
        """Checks the signatures and hashes of a list of events.

        If a PDU fails its signature check then we check if we have it in
        the database, and if not then request it from the sender's server (if that
        is different from `origin`). If that still fails, the event is omitted from
        the returned list.

        If a PDU fails its content hash check then it is redacted.

        Also runs each event through the spam checker; if it fails, redacts the event
        and flags it as soft-failed.

        The given list of PDUs are not modified; instead the function returns
        a new list.

        Args:
            origin: The server that sent us these events
            pdus: The events to be checked
            room_version: the version of the room these events are in

        Returns:
            A list of PDUs that have valid signatures and hashes.
        """

        # We limit how many PDUs we check at once, as if we try to do hundreds
        # of thousands of PDUs at once we see large memory spikes.

        valid_pdus = []

        async def _execute(pdu: EventBase) -> None:
            valid_pdu = await self._check_sigs_and_hash_and_fetch_one(
                pdu=pdu,
                origin=origin,
                room_version=room_version,
            )

            if valid_pdu:
                valid_pdus.append(valid_pdu)

        await concurrently_execute(_execute, pdus, 10000)

        return valid_pdus

    async def _check_sigs_and_hash_and_fetch_one(
        self,
        pdu: EventBase,
        origin: str,
        room_version: RoomVersion,
    ) -> Optional[EventBase]:
        """Takes a PDU and checks its signatures and hashes.

        If the PDU fails its signature check then we check if we have it in the
        database; if not, we then request it from sender's server (if that is not the
        same as `origin`). If that still fails, we return None.

        If the PDU fails its content hash check, it is redacted.

        Also runs the event through the spam checker; if it fails, redacts the event
        and flags it as soft-failed.

        Args:
            origin
            pdu
            room_version

        Returns:
            The PDU (possibly redacted) if it has valid signatures and hashes.
            None if no valid copy could be found.
        """

        try:
            return await self._check_sigs_and_hash(room_version, pdu)
        except InvalidEventSignatureError as e:
            logger.warning(
                "Signature on retrieved event %s was invalid (%s). "
                "Checking local store/orgin server",
                pdu.event_id,
                e,
            )

        # Check local db.
        res = await self.store.get_event(
            pdu.event_id, allow_rejected=True, allow_none=True
        )

        pdu_origin = get_domain_from_id(pdu.sender)
        if not res and pdu_origin != origin:
            try:
                res = await self.get_pdu(
                    destinations=[pdu_origin],
                    event_id=pdu.event_id,
                    room_version=room_version,
                    timeout=10000,
                )
            except SynapseError:
                pass

        if not res:
            logger.warning(
                "Failed to find copy of %s with valid signature", pdu.event_id
            )

        return res

    async def get_event_auth(
        self, destination: str, room_id: str, event_id: str
    ) -> List[EventBase]:
        res = await self.transport_layer.get_event_auth(destination, room_id, event_id)

        room_version = await self.store.get_room_version(room_id)

        auth_chain = [event_from_pdu_json(p, room_version) for p in res["auth_chain"]]

        signed_auth = await self._check_sigs_and_hash_and_fetch(
            destination, auth_chain, room_version=room_version
        )

        return signed_auth

    def _is_unknown_endpoint(
        self, e: HttpResponseException, synapse_error: Optional[SynapseError] = None
    ) -> bool:
        """
        Returns true if the response was due to an endpoint being unimplemented.

        Args:
            e: The error response received from the remote server.
            synapse_error: The above error converted to a SynapseError. This is
                automatically generated if not provided.

        """
        if synapse_error is None:
            synapse_error = e.to_synapse_error()
        # There is no good way to detect an "unknown" endpoint.
        #
        # Dendrite returns a 404 (with a body of "404 page not found");
        # Conduit returns a 404 (with no body); and Synapse returns a 400
        # with M_UNRECOGNIZED.
        #
        # This needs to be rather specific as some endpoints truly do return 404
        # errors.
        return (
            e.code == 404 and (not e.response or e.response == b"404 page not found")
        ) or (e.code == 400 and synapse_error.errcode == Codes.UNRECOGNIZED)

    async def _try_destination_list(
        self,
        description: str,
        destinations: Iterable[str],
        callback: Callable[[str], Awaitable[T]],
        failover_errcodes: Optional[Container[str]] = None,
        failover_on_unknown_endpoint: bool = False,
    ) -> T:
        """Try an operation on a series of servers, until it succeeds

        Args:
            description: description of the operation we're doing, for logging

            destinations: list of server_names to try

            callback:  Function to run for each server. Passed a single
                argument: the server_name to try.

                If the callback raises a CodeMessageException with a 300/400 code or
                an UnsupportedRoomVersionError, attempts to perform the operation
                stop immediately and the exception is reraised.

                Otherwise, if the callback raises an Exception the error is logged and the
                next server tried. Normally the stacktrace is logged but this is
                suppressed if the exception is an InvalidResponseError.

            failover_errcodes: Error codes (specific to this endpoint) which should
                cause a failover when received as part of an HTTP 400 error.

            failover_on_unknown_endpoint: if True, we will try other servers if it looks
                like a server doesn't support the endpoint. This is typically useful
                if the endpoint in question is new or experimental.

        Returns:
            The result of callback, if it succeeds

        Raises:
            SynapseError if the chosen remote server returns a 300/400 code, or
            no servers were reachable.
        """
        if failover_errcodes is None:
            failover_errcodes = ()

        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                return await callback(destination)
            except (
                RequestSendFailed,
                InvalidResponseError,
                NotRetryingDestination,
            ) as e:
                logger.warning("Failed to %s via %s: %s", description, destination, e)
            except UnsupportedRoomVersionError:
                raise
            except HttpResponseException as e:
                synapse_error = e.to_synapse_error()
                failover = False

                # Failover should occur:
                #
                # * On internal server errors.
                # * If the destination responds that it cannot complete the request.
                # * If the destination doesn't implemented the endpoint for some reason.
                if 500 <= e.code < 600:
                    failover = True

                elif e.code == 400 and synapse_error.errcode in failover_errcodes:
                    failover = True

                elif failover_on_unknown_endpoint and self._is_unknown_endpoint(
                    e, synapse_error
                ):
                    failover = True

                if not failover:
                    raise synapse_error from e

                logger.warning(
                    "Failed to %s via %s: %i %s",
                    description,
                    destination,
                    e.code,
                    e.args[0],
                )
            except Exception:
                logger.warning(
                    "Failed to %s via %s", description, destination, exc_info=True
                )

        raise SynapseError(502, "Failed to %s via any server" % (description,))

    async def make_membership_event(
        self,
        destinations: Iterable[str],
        room_id: str,
        user_id: str,
        membership: str,
        content: dict,
        params: Optional[Mapping[str, Union[str, Iterable[str]]]],
    ) -> Tuple[str, EventBase, RoomVersion]:
        """
        Creates an m.room.member event, with context, without participating in the room.

        Does so by asking one of the already participating servers to create an
        event with proper context.

        Returns a fully signed and hashed event.

        Note that this does not append any events to any graphs.

        Args:
            destinations: Candidate homeservers which are probably
                participating in the room.
            room_id: The room in which the event will happen.
            user_id: The user whose membership is being evented.
            membership: The "membership" property of the event. Must be one of
                "join" or "leave".
            content: Any additional data to put into the content field of the
                event.
            params: Query parameters to include in the request.

        Returns:
            `(origin, event, room_version)` where origin is the remote
            homeserver which generated the event, and room_version is the
            version of the room.

        Raises:
            UnsupportedRoomVersionError: if remote responds with
                a room version we don't understand.

            SynapseError: if the chosen remote server returns a 300/400 code, or
                no servers successfully handle the request.
        """
        valid_memberships = {Membership.JOIN, Membership.LEAVE, Membership.KNOCK}

        if membership not in valid_memberships:
            raise RuntimeError(
                "make_membership_event called with membership='%s', must be one of %s"
                % (membership, ",".join(valid_memberships))
            )

        async def send_request(destination: str) -> Tuple[str, EventBase, RoomVersion]:
            ret = await self.transport_layer.make_membership_event(
                destination, room_id, user_id, membership, params
            )

            # Note: If not supplied, the room version may be either v1 or v2,
            # however either way the event format version will be v1.
            room_version_id = ret.get("room_version", RoomVersions.V1.identifier)
            room_version = KNOWN_ROOM_VERSIONS.get(room_version_id)
            if not room_version:
                raise UnsupportedRoomVersionError()

            if not room_version.msc2403_knocking and membership == Membership.KNOCK:
                raise SynapseError(
                    400,
                    "This room version does not support knocking",
                    errcode=Codes.FORBIDDEN,
                )

            pdu_dict = ret.get("event", None)
            if not isinstance(pdu_dict, dict):
                raise InvalidResponseError("Bad 'event' field in response")

            logger.debug("Got response to make_%s: %s", membership, pdu_dict)

            pdu_dict["content"].update(content)

            # The protoevent received over the JSON wire may not have all
            # the required fields. Lets just gloss over that because
            # there's some we never care about
            if "prev_state" not in pdu_dict:
                pdu_dict["prev_state"] = []

            ev = builder.create_local_event_from_event_dict(
                self._clock,
                self.hostname,
                self.signing_key,
                room_version=room_version,
                event_dict=pdu_dict,
            )

            return destination, ev, room_version

        # MSC3083 defines additional error codes for room joins. Unfortunately
        # we do not yet know the room version, assume these will only be returned
        # by valid room versions.
        failover_errcodes = (
            (Codes.UNABLE_AUTHORISE_JOIN, Codes.UNABLE_TO_GRANT_JOIN)
            if membership == Membership.JOIN
            else None
        )

        return await self._try_destination_list(
            "make_" + membership,
            destinations,
            send_request,
            failover_errcodes=failover_errcodes,
        )

    async def send_join(
        self, destinations: Iterable[str], pdu: EventBase, room_version: RoomVersion
    ) -> SendJoinResult:
        """Sends a join event to one of a list of homeservers.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        Args:
            destinations: Candidate homeservers which are probably
                participating in the room.
            pdu: event to be sent
            room_version: the version of the room (according to the server that
                did the make_join)

        Returns:
            The result of the send join request.

        Raises:
            SynapseError: if the chosen remote server returns a 300/400 code, or
                no servers successfully handle the request.
        """

        async def send_request(destination: str) -> SendJoinResult:
            response = await self._do_send_join(room_version, destination, pdu)

            # If an event was returned (and expected to be returned):
            #
            # * Ensure it has the same event ID (note that the event ID is a hash
            #   of the event fields for versions which support MSC3083).
            # * Ensure the signatures are good.
            #
            # Otherwise, fallback to the provided event.
            if room_version.msc3083_join_rules and response.event:
                event = response.event

                valid_pdu = await self._check_sigs_and_hash_and_fetch_one(
                    pdu=event,
                    origin=destination,
                    room_version=room_version,
                )

                if valid_pdu is None or event.event_id != pdu.event_id:
                    raise InvalidResponseError("Returned an invalid join event")
            else:
                event = pdu

            state = response.state
            auth_chain = response.auth_events

            create_event = None
            for e in state:
                if (e.type, e.state_key) == (EventTypes.Create, ""):
                    create_event = e
                    break

            if create_event is None:
                # If the state doesn't have a create event then the room is
                # invalid, and it would fail auth checks anyway.
                raise InvalidResponseError("No create event in state")

            # the room version should be sane.
            create_room_version = create_event.content.get(
                "room_version", RoomVersions.V1.identifier
            )
            if create_room_version != room_version.identifier:
                # either the server that fulfilled the make_join, or the server that is
                # handling the send_join, is lying.
                raise InvalidResponseError(
                    "Unexpected room version %s in create event"
                    % (create_room_version,)
                )

            logger.info(
                "Processing from send_join %d events", len(state) + len(auth_chain)
            )

            # We now go and check the signatures and hashes for the event. Note
            # that we limit how many events we process at a time to keep the
            # memory overhead from exploding.
            valid_pdus_map: Dict[str, EventBase] = {}

            async def _execute(pdu: EventBase) -> None:
                valid_pdu = await self._check_sigs_and_hash_and_fetch_one(
                    pdu=pdu,
                    origin=destination,
                    room_version=room_version,
                )

                if valid_pdu:
                    valid_pdus_map[valid_pdu.event_id] = valid_pdu

            await concurrently_execute(
                _execute, itertools.chain(state, auth_chain), 10000
            )

            # NB: We *need* to copy to ensure that we don't have multiple
            # references being passed on, as that causes... issues.
            signed_state = [
                copy.copy(valid_pdus_map[p.event_id])
                for p in state
                if p.event_id in valid_pdus_map
            ]

            signed_auth = [
                valid_pdus_map[p.event_id]
                for p in auth_chain
                if p.event_id in valid_pdus_map
            ]

            # NB: We *need* to copy to ensure that we don't have multiple
            # references being passed on, as that causes... issues.
            for s in signed_state:
                s.internal_metadata = copy.deepcopy(s.internal_metadata)

            # double-check that the auth chain doesn't include a different create event
            auth_chain_create_events = [
                e.event_id
                for e in signed_auth
                if (e.type, e.state_key) == (EventTypes.Create, "")
            ]
            if auth_chain_create_events and auth_chain_create_events != [
                create_event.event_id
            ]:
                raise InvalidResponseError(
                    "Unexpected create event(s) in auth chain: %s"
                    % (auth_chain_create_events,)
                )

            if response.partial_state and not response.servers_in_room:
                raise InvalidResponseError(
                    "partial_state was set, but no servers were listed in the room"
                )

            return SendJoinResult(
                event=event,
                state=signed_state,
                auth_chain=signed_auth,
                origin=destination,
                partial_state=response.partial_state,
                servers_in_room=response.servers_in_room or [],
            )

        # MSC3083 defines additional error codes for room joins.
        failover_errcodes = None
        if room_version.msc3083_join_rules:
            failover_errcodes = (
                Codes.UNABLE_AUTHORISE_JOIN,
                Codes.UNABLE_TO_GRANT_JOIN,
            )

            # If the join is being authorised via allow rules, we need to send
            # the /send_join back to the same server that was originally used
            # with /make_join.
            if EventContentFields.AUTHORISING_USER in pdu.content:
                destinations = [
                    get_domain_from_id(pdu.content[EventContentFields.AUTHORISING_USER])
                ]

        return await self._try_destination_list(
            "send_join", destinations, send_request, failover_errcodes=failover_errcodes
        )

    async def _do_send_join(
        self, room_version: RoomVersion, destination: str, pdu: EventBase
    ) -> SendJoinResponse:
        time_now = self._clock.time_msec()

        try:
            return await self.transport_layer.send_join_v2(
                room_version=room_version,
                destination=destination,
                room_id=pdu.room_id,
                event_id=pdu.event_id,
                content=pdu.get_pdu_json(time_now),
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the v1 endpoint. Otherwise, consider it a legitimate error
            # and raise.
            if not self._is_unknown_endpoint(e):
                raise

        logger.debug("Couldn't send_join with the v2 API, falling back to the v1 API")

        return await self.transport_layer.send_join_v1(
            room_version=room_version,
            destination=destination,
            room_id=pdu.room_id,
            event_id=pdu.event_id,
            content=pdu.get_pdu_json(time_now),
        )

    async def send_invite(
        self,
        destination: str,
        room_id: str,
        event_id: str,
        pdu: EventBase,
    ) -> EventBase:
        room_version = await self.store.get_room_version(room_id)

        content = await self._do_send_invite(destination, pdu, room_version)

        pdu_dict = content["event"]

        logger.debug("Got response to send_invite: %s", pdu_dict)

        pdu = event_from_pdu_json(pdu_dict, room_version)

        # Check signatures are correct.
        try:
            pdu = await self._check_sigs_and_hash(room_version, pdu)
        except InvalidEventSignatureError as e:
            errmsg = f"event id {pdu.event_id}: {e}"
            logger.warning("%s", errmsg)
            raise SynapseError(403, errmsg, Codes.FORBIDDEN)

            # FIXME: We should handle signature failures more gracefully.

        return pdu

    async def _do_send_invite(
        self, destination: str, pdu: EventBase, room_version: RoomVersion
    ) -> JsonDict:
        """Actually sends the invite, first trying v2 API and falling back to
        v1 API if necessary.

        Returns:
            The event as a dict as returned by the remote server

        Raises:
            SynapseError: if the remote server returns an error or if the server
                only supports the v1 endpoint and a room version other than "1"
                or "2" is requested.
        """
        time_now = self._clock.time_msec()

        try:
            return await self.transport_layer.send_invite_v2(
                destination=destination,
                room_id=pdu.room_id,
                event_id=pdu.event_id,
                content={
                    "event": pdu.get_pdu_json(time_now),
                    "room_version": room_version.identifier,
                    "invite_room_state": pdu.unsigned.get("invite_room_state", []),
                },
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the v1 endpoint if the room uses old-style event IDs.
            # Otherwise, consider it a legitimate error and raise.
            err = e.to_synapse_error()
            if self._is_unknown_endpoint(e, err):
                if room_version.event_format != EventFormatVersions.V1:
                    raise SynapseError(
                        400,
                        "User's homeserver does not support this room version",
                        Codes.UNSUPPORTED_ROOM_VERSION,
                    )
            else:
                raise err

        # Didn't work, try v1 API.
        # Note the v1 API returns a tuple of `(200, content)`

        _, content = await self.transport_layer.send_invite_v1(
            destination=destination,
            room_id=pdu.room_id,
            event_id=pdu.event_id,
            content=pdu.get_pdu_json(time_now),
        )
        return content

    async def send_leave(self, destinations: Iterable[str], pdu: EventBase) -> None:
        """Sends a leave event to one of a list of homeservers.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        This is mostly useful to reject received invites.

        Args:
            destinations: Candidate homeservers which are probably
                participating in the room.
            pdu: event to be sent

        Raises:
            SynapseError: if the chosen remote server returns a 300/400 code, or
                no servers successfully handle the request.
        """

        async def send_request(destination: str) -> None:
            content = await self._do_send_leave(destination, pdu)
            logger.debug("Got content: %s", content)

        return await self._try_destination_list(
            "send_leave", destinations, send_request
        )

    async def _do_send_leave(self, destination: str, pdu: EventBase) -> JsonDict:
        time_now = self._clock.time_msec()

        try:
            return await self.transport_layer.send_leave_v2(
                destination=destination,
                room_id=pdu.room_id,
                event_id=pdu.event_id,
                content=pdu.get_pdu_json(time_now),
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the v1 endpoint. Otherwise, consider it a legitimate error
            # and raise.
            if not self._is_unknown_endpoint(e):
                raise

        logger.debug("Couldn't send_leave with the v2 API, falling back to the v1 API")

        resp = await self.transport_layer.send_leave_v1(
            destination=destination,
            room_id=pdu.room_id,
            event_id=pdu.event_id,
            content=pdu.get_pdu_json(time_now),
        )

        # We expect the v1 API to respond with [200, content], so we only return the
        # content.
        return resp[1]

    async def send_knock(self, destinations: List[str], pdu: EventBase) -> JsonDict:
        """Attempts to send a knock event to given a list of servers. Iterates
        through the list until one attempt succeeds.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        Args:
            destinations: A list of candidate homeservers which are likely to be
                participating in the room.
            pdu: The event to be sent.

        Returns:
            The remote homeserver return some state from the room. The response
            dictionary is in the form:

            {"knock_state_events": [<state event dict>, ...]}

            The list of state events may be empty.

        Raises:
            SynapseError: If the chosen remote server returns a 3xx/4xx code.
            RuntimeError: If no servers were reachable.
        """

        async def send_request(destination: str) -> JsonDict:
            return await self._do_send_knock(destination, pdu)

        return await self._try_destination_list(
            "send_knock", destinations, send_request
        )

    async def _do_send_knock(self, destination: str, pdu: EventBase) -> JsonDict:
        """Send a knock event to a remote homeserver.

        Args:
            destination: The homeserver to send to.
            pdu: The event to send.

        Returns:
            The remote homeserver can optionally return some state from the room. The response
            dictionary is in the form:

            {"knock_state_events": [<state event dict>, ...]}

            The list of state events may be empty.
        """
        time_now = self._clock.time_msec()

        return await self.transport_layer.send_knock_v1(
            destination=destination,
            room_id=pdu.room_id,
            event_id=pdu.event_id,
            content=pdu.get_pdu_json(time_now),
        )

    async def get_public_rooms(
        self,
        remote_server: str,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[Dict] = None,
        include_all_networks: bool = False,
        third_party_instance_id: Optional[str] = None,
    ) -> JsonDict:
        """Get the list of public rooms from a remote homeserver

        Args:
            remote_server: The name of the remote server
            limit: Maximum amount of rooms to return
            since_token: Used for result pagination
            search_filter: A filter dictionary to send the remote homeserver
                and filter the result set
            include_all_networks: Whether to include results from all third party instances
            third_party_instance_id: Whether to only include results from a specific third
                party instance

        Returns:
            The response from the remote server.

        Raises:
            HttpResponseException / RequestSendFailed: There was an exception
                returned from the remote server
            SynapseException: M_FORBIDDEN when the remote server has disallowed publicRoom
                requests over federation

        """
        return await self.transport_layer.get_public_rooms(
            remote_server,
            limit,
            since_token,
            search_filter,
            include_all_networks=include_all_networks,
            third_party_instance_id=third_party_instance_id,
        )

    async def get_missing_events(
        self,
        destination: str,
        room_id: str,
        earliest_events_ids: Iterable[str],
        latest_events: Iterable[EventBase],
        limit: int,
        min_depth: int,
        timeout: int,
    ) -> List[EventBase]:
        """Tries to fetch events we are missing. This is called when we receive
        an event without having received all of its ancestors.

        Args:
            destination
            room_id
            earliest_events_ids: List of event ids. Effectively the
                events we expected to receive, but haven't. `get_missing_events`
                should only return events that didn't happen before these.
            latest_events: List of events we have received that we don't
                have all previous events for.
            limit: Maximum number of events to return.
            min_depth: Minimum depth of events to return.
            timeout: Max time to wait in ms
        """
        try:
            content = await self.transport_layer.get_missing_events(
                destination=destination,
                room_id=room_id,
                earliest_events=earliest_events_ids,
                latest_events=[e.event_id for e in latest_events],
                limit=limit,
                min_depth=min_depth,
                timeout=timeout,
            )

            room_version = await self.store.get_room_version(room_id)

            events = [
                event_from_pdu_json(e, room_version) for e in content.get("events", [])
            ]

            signed_events = await self._check_sigs_and_hash_and_fetch(
                destination, events, room_version=room_version
            )
        except HttpResponseException as e:
            if not e.code == 400:
                raise

            # We are probably hitting an old server that doesn't support
            # get_missing_events
            signed_events = []

        return signed_events

    async def forward_third_party_invite(
        self, destinations: Iterable[str], room_id: str, event_dict: JsonDict
    ) -> None:
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                await self.transport_layer.exchange_third_party_invite(
                    destination=destination, room_id=room_id, event_dict=event_dict
                )
                return
            except CodeMessageException:
                raise
            except Exception as e:
                logger.exception(
                    "Failed to send_third_party_invite via %s: %s", destination, str(e)
                )

        raise RuntimeError("Failed to send to any server.")

    async def get_room_complexity(
        self, destination: str, room_id: str
    ) -> Optional[JsonDict]:
        """
        Fetch the complexity of a remote room from another server.

        Args:
            destination: The remote server
            room_id: The room ID to ask about.

        Returns:
            Dict contains the complexity metric versions, while None means we
            could not fetch the complexity.
        """
        try:
            return await self.transport_layer.get_room_complexity(
                destination=destination, room_id=room_id
            )
        except CodeMessageException as e:
            # We didn't manage to get it -- probably a 404. We are okay if other
            # servers don't give it to us.
            logger.debug(
                "Failed to fetch room complexity via %s for %s, got a %d",
                destination,
                room_id,
                e.code,
            )
        except Exception:
            logger.exception(
                "Failed to fetch room complexity via %s for %s", destination, room_id
            )

        # If we don't manage to find it, return None. It's not an error if a
        # server doesn't give it to us.
        return None

    async def get_room_hierarchy(
        self,
        destinations: Iterable[str],
        room_id: str,
        suggested_only: bool,
    ) -> Tuple[JsonDict, Sequence[JsonDict], Sequence[JsonDict], Sequence[str]]:
        """
        Call other servers to get a hierarchy of the given room.

        Performs simple data validates and parsing of the response.

        Args:
            destinations: The remote servers. We will try them in turn, omitting any
                that have been blacklisted.
            room_id: ID of the space to be queried
            suggested_only:  If true, ask the remote server to only return children
                with the "suggested" flag set

        Returns:
            A tuple of:
                The room as a JSON dictionary, without a "children_state" key.
                A list of `m.space.child` state events.
                A list of children rooms, as JSON dictionaries.
                A list of inaccessible children room IDs.

        Raises:
            SynapseError if we were unable to get a valid summary from any of the
               remote servers
        """

        cached_result = self._get_room_hierarchy_cache.get((room_id, suggested_only))
        if cached_result:
            return cached_result

        async def send_request(
            destination: str,
        ) -> Tuple[JsonDict, Sequence[JsonDict], Sequence[JsonDict], Sequence[str]]:
            try:
                res = await self.transport_layer.get_room_hierarchy(
                    destination=destination,
                    room_id=room_id,
                    suggested_only=suggested_only,
                )
            except HttpResponseException as e:
                # If an error is received that is due to an unrecognised endpoint,
                # fallback to the unstable endpoint. Otherwise, consider it a
                # legitimate error and raise.
                if not self._is_unknown_endpoint(e):
                    raise

                logger.debug(
                    "Couldn't fetch room hierarchy with the v1 API, falling back to the unstable API"
                )

                res = await self.transport_layer.get_room_hierarchy_unstable(
                    destination=destination,
                    room_id=room_id,
                    suggested_only=suggested_only,
                )

            room = res.get("room")
            if not isinstance(room, dict):
                raise InvalidResponseError("'room' must be a dict")
            if room.get("room_id") != room_id:
                raise InvalidResponseError("wrong room returned in hierarchy response")

            # Validate children_state of the room.
            children_state = room.pop("children_state", [])
            if not isinstance(children_state, list):
                raise InvalidResponseError("'room.children_state' must be a list")
            if any(not isinstance(e, dict) for e in children_state):
                raise InvalidResponseError("Invalid event in 'children_state' list")
            try:
                for child_state in children_state:
                    _validate_hierarchy_event(child_state)
            except ValueError as e:
                raise InvalidResponseError(str(e))

            # Validate the children rooms.
            children = res.get("children", [])
            if not isinstance(children, list):
                raise InvalidResponseError("'children' must be a list")
            if any(not isinstance(r, dict) for r in children):
                raise InvalidResponseError("Invalid room in 'children' list")

            # Validate the inaccessible children.
            inaccessible_children = res.get("inaccessible_children", [])
            if not isinstance(inaccessible_children, list):
                raise InvalidResponseError("'inaccessible_children' must be a list")
            if any(not isinstance(r, str) for r in inaccessible_children):
                raise InvalidResponseError(
                    "Invalid room ID in 'inaccessible_children' list"
                )

            return room, children_state, children, inaccessible_children

        result = await self._try_destination_list(
            "fetch room hierarchy",
            destinations,
            send_request,
            failover_on_unknown_endpoint=True,
        )

        # Cache the result to avoid fetching data over federation every time.
        self._get_room_hierarchy_cache[(room_id, suggested_only)] = result
        return result

    async def timestamp_to_event(
        self, destination: str, room_id: str, timestamp: int, direction: str
    ) -> "TimestampToEventResponse":
        """
        Calls a remote federating server at `destination` asking for their
        closest event to the given timestamp in the given direction. Also
        validates the response to always return the expected keys or raises an
        error.

        Args:
            destination: Domain name of the remote homeserver
            room_id: Room to fetch the event from
            timestamp: The point in time (inclusive) we should navigate from in
                the given direction to find the closest event.
            direction: ["f"|"b"] to indicate whether we should navigate forward
                or backward from the given timestamp to find the closest event.

        Returns:
            A parsed TimestampToEventResponse including the closest event_id
            and origin_server_ts

        Raises:
            Various exceptions when the request fails
            InvalidResponseError when the response does not have the correct
            keys or wrong types
        """
        remote_response = await self.transport_layer.timestamp_to_event(
            destination, room_id, timestamp, direction
        )

        if not isinstance(remote_response, dict):
            raise InvalidResponseError(
                "Response must be a JSON dictionary but received %r" % remote_response
            )

        try:
            return TimestampToEventResponse.from_json_dict(remote_response)
        except ValueError as e:
            raise InvalidResponseError(str(e))

    async def get_account_status(
        self, destination: str, user_ids: List[str]
    ) -> Tuple[JsonDict, List[str]]:
        """Retrieves account statuses for a given list of users on a given remote
        homeserver.

        If the request fails for any reason, all user IDs for this destination are marked
        as failed.

        Args:
            destination: the destination to contact
            user_ids: the user ID(s) for which to request account status(es)

        Returns:
            The account statuses, as well as the list of user IDs for which it was not
            possible to retrieve a status.
        """
        try:
            res = await self.transport_layer.get_account_status(destination, user_ids)
        except Exception:
            # If the query failed for any reason, mark all the users as failed.
            return {}, user_ids

        statuses = res.get("account_statuses", {})
        failures = res.get("failures", [])

        if not isinstance(statuses, dict) or not isinstance(failures, list):
            # Make sure we're not feeding back malformed data back to the caller.
            logger.warning(
                "Destination %s responded with malformed data to account_status query",
                destination,
            )
            return {}, user_ids

        for user_id in user_ids:
            # Any account whose status is missing is a user we failed to receive the
            # status of.
            if user_id not in statuses and user_id not in failures:
                failures.append(user_id)

        # Filter out any user ID that doesn't belong to the remote server that sent its
        # status (or failure).
        def filter_user_id(user_id: str) -> bool:
            try:
                return UserID.from_string(user_id).domain == destination
            except SynapseError:
                # If the user ID doesn't parse, ignore it.
                return False

        filtered_statuses = dict(
            # item is a (key, value) tuple, so item[0] is the user ID.
            filter(lambda item: filter_user_id(item[0]), statuses.items())
        )

        filtered_failures = list(filter(filter_user_id, failures))

        return filtered_statuses, filtered_failures


@attr.s(frozen=True, slots=True, auto_attribs=True)
class TimestampToEventResponse:
    """Typed response dictionary for the federation /timestamp_to_event endpoint"""

    event_id: str
    origin_server_ts: int

    # the raw data, including the above keys
    data: JsonDict

    @classmethod
    def from_json_dict(cls, d: JsonDict) -> "TimestampToEventResponse":
        """Parsed response from the federation /timestamp_to_event endpoint

        Args:
            d: JSON object response to be parsed

        Raises:
            ValueError if d does not the correct keys or they are the wrong types
        """

        event_id = d.get("event_id")
        if not isinstance(event_id, str):
            raise ValueError(
                "Invalid response: 'event_id' must be a str but received %r" % event_id
            )

        origin_server_ts = d.get("origin_server_ts")
        if not isinstance(origin_server_ts, int):
            raise ValueError(
                "Invalid response: 'origin_server_ts' must be a int but received %r"
                % origin_server_ts
            )

        return cls(event_id, origin_server_ts, d)


def _validate_hierarchy_event(d: JsonDict) -> None:
    """Validate an event within the result of a /hierarchy request

    Args:
        d: json object to be parsed

    Raises:
        ValueError if d is not a valid event
    """

    event_type = d.get("type")
    if not isinstance(event_type, str):
        raise ValueError("Invalid event: 'event_type' must be a str")

    state_key = d.get("state_key")
    if not isinstance(state_key, str):
        raise ValueError("Invalid event: 'state_key' must be a str")

    content = d.get("content")
    if not isinstance(content, dict):
        raise ValueError("Invalid event: 'content' must be a dict")

    via = content.get("via")
    if not isinstance(via, list):
        raise ValueError("Invalid event: 'via' must be a list")
    if any(not isinstance(v, str) for v in via):
        raise ValueError("Invalid event: 'via' must be a list of strings")
