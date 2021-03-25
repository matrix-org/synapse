# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

from prometheus_client import Counter

from twisted.internet import defer
from twisted.internet.defer import Deferred

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import (
    CodeMessageException,
    Codes,
    FederationDeniedError,
    HttpResponseException,
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
from synapse.federation.federation_base import FederationBase, event_from_pdu_json
from synapse.logging.context import make_deferred_yieldable, preserve_fn
from synapse.logging.utils import log_function
from synapse.types import JsonDict, get_domain_from_id
from synapse.util import unwrapFirstError
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.retryutils import NotRetryingDestination

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)

sent_queries_counter = Counter("synapse_federation_client_sent_queries", "", ["type"])


PDU_RETRY_TIME_MS = 1 * 60 * 1000

T = TypeVar("T")


class InvalidResponseError(RuntimeError):
    """Helper for _try_destination_list: indicates that the server returned a response
    we couldn't parse
    """

    pass


class FederationClient(FederationBase):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.pdu_destination_tried = {}  # type: Dict[str, Dict[str, int]]
        self._clock.looping_call(self._clear_tried_cache, 60 * 1000)
        self.state = hs.get_state_handler()
        self.transport_layer = hs.get_federation_transport_client()

        self.hostname = hs.hostname
        self.signing_key = hs.signing_key

        self._get_pdu_cache = ExpiringCache(
            cache_name="get_pdu_cache",
            clock=self._clock,
            max_len=1000,
            expiry_ms=120 * 1000,
            reset_expiry_on_get=False,
        )

    def _clear_tried_cache(self):
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

    @log_function
    async def make_query(
        self,
        destination: str,
        query_type: str,
        args: dict,
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

    @log_function
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

    @log_function
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

    @log_function
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
        self, dest: str, room_id: str, limit: int, extremities: Iterable[str]
    ) -> Optional[List[EventBase]]:
        """Requests some more historic PDUs for the given room from the
        given destination server.

        Args:
            dest: The remote homeserver to ask.
            room_id: The room_id to backfill.
            limit: The maximum number of events to return.
            extremities: our current backwards extremities, to backfill from
        """
        logger.debug("backfill extrem=%s", extremities)

        # If there are no extremities then we've (probably) reached the start.
        if not extremities:
            return None

        transaction_data = await self.transport_layer.backfill(
            dest, room_id, extremities, limit
        )

        logger.debug("backfill transaction_data=%r", transaction_data)

        room_version = await self.store.get_room_version(room_id)

        pdus = [
            event_from_pdu_json(p, room_version, outlier=False)
            for p in transaction_data["pdus"]
        ]

        # Check signatures and hash of pdus, removing any from the list that fail checks
        pdus[:] = await self._check_sigs_and_hash_and_fetch(
            dest, pdus, outlier=True, room_version=room_version
        )

        return pdus

    async def get_pdu(
        self,
        destinations: Iterable[str],
        event_id: str,
        room_version: RoomVersion,
        outlier: bool = False,
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
            outlier: Indicates whether the PDU is an `outlier`, i.e. if
                it's from an arbitrary point in the context as opposed to part
                of the current block of PDUs. Defaults to `False`
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
                transaction_data = await self.transport_layer.get_event(
                    destination, event_id, timeout=timeout
                )

                logger.debug(
                    "retrieved event id %s from %s: %r",
                    event_id,
                    destination,
                    transaction_data,
                )

                pdu_list = [
                    event_from_pdu_json(p, room_version, outlier=outlier)
                    for p in transaction_data["pdus"]
                ]  # type: List[EventBase]

                if pdu_list and pdu_list[0]:
                    pdu = pdu_list[0]

                    # Check signatures are correct.
                    signed_pdu = await self._check_sigs_and_hash(room_version, pdu)

                    break

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
        """
        result = await self.transport_layer.get_room_state_ids(
            destination, room_id, event_id=event_id
        )

        state_event_ids = result["pdu_ids"]
        auth_event_ids = result.get("auth_chain_ids", [])

        if not isinstance(state_event_ids, list) or not isinstance(
            auth_event_ids, list
        ):
            raise Exception("invalid response from /state_ids")

        return state_event_ids, auth_event_ids

    async def _check_sigs_and_hash_and_fetch(
        self,
        origin: str,
        pdus: List[EventBase],
        room_version: RoomVersion,
        outlier: bool = False,
        include_none: bool = False,
    ) -> List[EventBase]:
        """Takes a list of PDUs and checks the signatures and hashes of each
        one. If a PDU fails its signature check then we check if we have it in
        the database and if not then request if from the originating server of
        that PDU.

        If a PDU fails its content hash check then it is redacted.

        The given list of PDUs are not modified, instead the function returns
        a new list.

        Args:
            origin
            pdu
            room_version
            outlier: Whether the events are outliers or not
            include_none: Whether to include None in the returned list
                for events that have failed their checks

        Returns:
            A list of PDUs that have valid signatures and hashes.
        """
        deferreds = self._check_sigs_and_hashes(room_version, pdus)

        async def handle_check_result(pdu: EventBase, deferred: Deferred):
            try:
                res = await make_deferred_yieldable(deferred)
            except SynapseError:
                res = None

            if not res:
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
                        outlier=outlier,
                        timeout=10000,
                    )
                except SynapseError:
                    pass

            if not res:
                logger.warning(
                    "Failed to find copy of %s with valid signature", pdu.event_id
                )

            return res

        handle = preserve_fn(handle_check_result)
        deferreds2 = [handle(pdu, deferred) for pdu, deferred in zip(pdus, deferreds)]

        valid_pdus = await make_deferred_yieldable(
            defer.gatherResults(deferreds2, consumeErrors=True)
        ).addErrback(unwrapFirstError)

        if include_none:
            return valid_pdus
        else:
            return [p for p in valid_pdus if p]

    async def get_event_auth(
        self, destination: str, room_id: str, event_id: str
    ) -> List[EventBase]:
        res = await self.transport_layer.get_event_auth(destination, room_id, event_id)

        room_version = await self.store.get_room_version(room_id)

        auth_chain = [
            event_from_pdu_json(p, room_version, outlier=True)
            for p in res["auth_chain"]
        ]

        signed_auth = await self._check_sigs_and_hash_and_fetch(
            destination, auth_chain, outlier=True, room_version=room_version
        )

        signed_auth.sort(key=lambda e: e.depth)

        return signed_auth

    async def _try_destination_list(
        self,
        description: str,
        destinations: Iterable[str],
        callback: Callable[[str], Awaitable[T]],
    ) -> T:
        """Try an operation on a series of servers, until it succeeds

        Args:
            description: description of the operation we're doing, for logging

            destinations: list of server_names to try

            callback:  Function to run for each server. Passed a single
                argument: the server_name to try.

                If the callback raises a CodeMessageException with a 300/400 code,
                attempts to perform the operation stop immediately and the exception is
                reraised.

                Otherwise, if the callback raises an Exception the error is logged and the
                next server tried. Normally the stacktrace is logged but this is
                suppressed if the exception is an InvalidResponseError.

        Returns:
            The result of callback, if it succeeds

        Raises:
            SynapseError if the chosen remote server returns a 300/400 code, or
            no servers were reachable.
        """
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                res = await callback(destination)
                return res
            except InvalidResponseError as e:
                logger.warning("Failed to %s via %s: %s", description, destination, e)
            except UnsupportedRoomVersionError:
                raise
            except HttpResponseException as e:
                if not 500 <= e.code < 600:
                    raise e.to_synapse_error()
                else:
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

            SynapseError: if the chosen remote server returns a 300/400 code.

            RuntimeError: if no servers were reachable.
        """
        valid_memberships = {Membership.JOIN, Membership.LEAVE}
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

        return await self._try_destination_list(
            "make_" + membership, destinations, send_request
        )

    async def send_join(
        self, destinations: Iterable[str], pdu: EventBase, room_version: RoomVersion
    ) -> Dict[str, Any]:
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
            a dict with members ``origin`` (a string
            giving the server the event was sent to, ``state`` (?) and
            ``auth_chain``.

        Raises:
            SynapseError: if the chosen remote server returns a 300/400 code.

            RuntimeError: if no servers were reachable.
        """

        async def send_request(destination) -> Dict[str, Any]:
            content = await self._do_send_join(destination, pdu)

            logger.debug("Got content: %s", content)

            state = [
                event_from_pdu_json(p, room_version, outlier=True)
                for p in content.get("state", [])
            ]

            auth_chain = [
                event_from_pdu_json(p, room_version, outlier=True)
                for p in content.get("auth_chain", [])
            ]

            pdus = {p.event_id: p for p in itertools.chain(state, auth_chain)}

            create_event = None
            for e in state:
                if (e.type, e.state_key) == (EventTypes.Create, ""):
                    create_event = e
                    break

            if create_event is None:
                # If the state doesn't have a create event then the room is
                # invalid, and it would fail auth checks anyway.
                raise SynapseError(400, "No create event in state")

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

            valid_pdus = await self._check_sigs_and_hash_and_fetch(
                destination,
                list(pdus.values()),
                outlier=True,
                room_version=room_version,
            )

            valid_pdus_map = {p.event_id: p for p in valid_pdus}

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

            # double-check that the same create event has ended up in the auth chain
            auth_chain_create_events = [
                e.event_id
                for e in signed_auth
                if (e.type, e.state_key) == (EventTypes.Create, "")
            ]
            if auth_chain_create_events != [create_event.event_id]:
                raise InvalidResponseError(
                    "Unexpected create event(s) in auth chain: %s"
                    % (auth_chain_create_events,)
                )

            return {
                "state": signed_state,
                "auth_chain": signed_auth,
                "origin": destination,
            }

        return await self._try_destination_list("send_join", destinations, send_request)

    async def _do_send_join(self, destination: str, pdu: EventBase) -> JsonDict:
        time_now = self._clock.time_msec()

        try:
            return await self.transport_layer.send_join_v2(
                destination=destination,
                room_id=pdu.room_id,
                event_id=pdu.event_id,
                content=pdu.get_pdu_json(time_now),
            )
        except HttpResponseException as e:
            if e.code in [400, 404]:
                err = e.to_synapse_error()

                # If we receive an error response that isn't a generic error, or an
                # unrecognised endpoint error, we  assume that the remote understands
                # the v2 invite API and this is a legitimate error.
                if err.errcode not in [Codes.UNKNOWN, Codes.UNRECOGNIZED]:
                    raise err
            else:
                raise e.to_synapse_error()

        logger.debug("Couldn't send_join with the v2 API, falling back to the v1 API")

        resp = await self.transport_layer.send_join_v1(
            destination=destination,
            room_id=pdu.room_id,
            event_id=pdu.event_id,
            content=pdu.get_pdu_json(time_now),
        )

        # We expect the v1 API to respond with [200, content], so we only return the
        # content.
        return resp[1]

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
        pdu = await self._check_sigs_and_hash(room_version, pdu)

        # FIXME: We should handle signature failures more gracefully.

        return pdu

    async def _do_send_invite(
        self, destination: str, pdu: EventBase, room_version: RoomVersion
    ) -> JsonDict:
        """Actually sends the invite, first trying v2 API and falling back to
        v1 API if necessary.

        Returns:
            The event as a dict as returned by the remote server
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
            if e.code in [400, 404]:
                err = e.to_synapse_error()

                # If we receive an error response that isn't a generic error, we
                # assume that the remote understands the v2 invite API and this
                # is a legitimate error.
                if err.errcode != Codes.UNKNOWN:
                    raise err

                # Otherwise, we assume that the remote server doesn't understand
                # the v2 invite API. That's ok provided the room uses old-style event
                # IDs.
                if room_version.event_format != EventFormatVersions.V1:
                    raise SynapseError(
                        400,
                        "User's homeserver does not support this room version",
                        Codes.UNSUPPORTED_ROOM_VERSION,
                    )
            elif e.code in (403, 429):
                raise e.to_synapse_error()
            else:
                raise

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
            SynapseError if the chosen remote server returns a 300/400 code.

            RuntimeError if no servers were reachable.
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
            if e.code in [400, 404]:
                err = e.to_synapse_error()

                # If we receive an error response that isn't a generic error, or an
                # unrecognised endpoint error, we  assume that the remote understands
                # the v2 invite API and this is a legitimate error.
                if err.errcode not in [Codes.UNKNOWN, Codes.UNRECOGNIZED]:
                    raise err
            else:
                raise e.to_synapse_error()

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
            HttpResponseException: There was an exception returned from the remote server
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
                destination, events, outlier=False, room_version=room_version
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
