# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2019-2021 Matrix.org Federation C.I.C
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
import random
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Collection,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)

from matrix_common.regex import glob_to_regex
from prometheus_client import Counter, Gauge, Histogram

from twisted.internet.abstract import isIPAddress
from twisted.python import failure

from synapse.api.constants import EduTypes, EventContentFields, EventTypes, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    FederationError,
    IncompatibleRoomVersionError,
    NotFoundError,
    SynapseError,
    UnsupportedRoomVersionError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersion
from synapse.crypto.event_signing import compute_event_signature
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.federation.federation_base import (
    FederationBase,
    InvalidEventSignatureError,
    event_from_pdu_json,
)
from synapse.federation.persistence import TransactionActions
from synapse.federation.units import Edu, Transaction
from synapse.http.servlet import assert_params_in_dict
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    run_in_background,
)
from synapse.logging.opentracing import (
    log_kv,
    start_active_span_from_edu,
    tag_args,
    trace,
)
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.replication.http.federation import (
    ReplicationFederationSendEduRestServlet,
    ReplicationGetQueryRestServlet,
)
from synapse.storage.databases.main.events import PartialStateConflictError
from synapse.storage.databases.main.lock import Lock
from synapse.types import JsonDict, StateMap, get_domain_from_id
from synapse.util import json_decoder, unwrapFirstError
from synapse.util.async_helpers import Linearizer, concurrently_execute, gather_results
from synapse.util.caches.response_cache import ResponseCache
from synapse.util.stringutils import parse_server_name

if TYPE_CHECKING:
    from synapse.server import HomeServer

# when processing incoming transactions, we try to handle multiple rooms in
# parallel, up to this limit.
TRANSACTION_CONCURRENCY_LIMIT = 10

logger = logging.getLogger(__name__)

received_pdus_counter = Counter("synapse_federation_server_received_pdus", "")

received_edus_counter = Counter("synapse_federation_server_received_edus", "")

received_queries_counter = Counter(
    "synapse_federation_server_received_queries", "", ["type"]
)

pdu_process_time = Histogram(
    "synapse_federation_server_pdu_process_time",
    "Time taken to process an event",
)

last_pdu_ts_metric = Gauge(
    "synapse_federation_last_received_pdu_time",
    "The timestamp of the last PDU which was successfully received from the given domain",
    labelnames=("server_name",),
)


# The name of the lock to use when process events in a room received over
# federation.
_INBOUND_EVENT_HANDLING_LOCK_NAME = "federation_inbound_pdu"


class FederationServer(FederationBase):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.handler = hs.get_federation_handler()
        self._spam_checker = hs.get_spam_checker()
        self._federation_event_handler = hs.get_federation_event_handler()
        self.state = hs.get_state_handler()
        self._event_auth_handler = hs.get_event_auth_handler()
        self._room_member_handler = hs.get_room_member_handler()

        self._state_storage_controller = hs.get_storage_controllers().state

        self.device_handler = hs.get_device_handler()

        # Ensure the following handlers are loaded since they register callbacks
        # with FederationHandlerRegistry.
        hs.get_directory_handler()

        self._server_linearizer = Linearizer("fed_server")

        # origins that we are currently processing a transaction from.
        # a dict from origin to txn id.
        self._active_transactions: Dict[str, str] = {}

        # We cache results for transaction with the same ID
        self._transaction_resp_cache: ResponseCache[Tuple[str, str]] = ResponseCache(
            hs.get_clock(), "fed_txn_handler", timeout_ms=30000
        )

        self.transaction_actions = TransactionActions(self.store)

        self.registry = hs.get_federation_registry()

        # We cache responses to state queries, as they take a while and often
        # come in waves.
        self._state_resp_cache: ResponseCache[
            Tuple[str, Optional[str]]
        ] = ResponseCache(hs.get_clock(), "state_resp", timeout_ms=30000)
        self._state_ids_resp_cache: ResponseCache[Tuple[str, str]] = ResponseCache(
            hs.get_clock(), "state_ids_resp", timeout_ms=30000
        )

        self._federation_metrics_domains = (
            hs.config.federation.federation_metrics_domains
        )

        self._room_prejoin_state_types = hs.config.api.room_prejoin_state

        # Whether we have started handling old events in the staging area.
        self._started_handling_of_staged_events = False

    @wrap_as_background_process("_handle_old_staged_events")
    async def _handle_old_staged_events(self) -> None:
        """Handle old staged events by fetching all rooms that have staged
        events and start the processing of each of those rooms.
        """

        # Get all the rooms IDs with staged events.
        room_ids = await self.store.get_all_rooms_with_staged_incoming_events()

        # We then shuffle them so that if there are multiple instances doing
        # this work they're less likely to collide.
        random.shuffle(room_ids)

        for room_id in room_ids:
            room_version = await self.store.get_room_version(room_id)

            # Try and acquire the processing lock for the room, if we get it start a
            # background process for handling the events in the room.
            lock = await self.store.try_acquire_lock(
                _INBOUND_EVENT_HANDLING_LOCK_NAME, room_id
            )
            if lock:
                logger.info("Handling old staged inbound events in %s", room_id)
                self._process_incoming_pdus_in_room_inner(
                    room_id,
                    room_version,
                    lock,
                )

            # We pause a bit so that we don't start handling all rooms at once.
            await self._clock.sleep(random.uniform(0, 0.1))

    async def on_backfill_request(
        self, origin: str, room_id: str, versions: List[str], limit: int
    ) -> Tuple[int, Dict[str, Any]]:
        async with self._server_linearizer.queue((origin, room_id)):
            origin_host, _ = parse_server_name(origin)
            await self.check_server_matches_acl(origin_host, room_id)

            pdus = await self.handler.on_backfill_request(
                origin, room_id, versions, limit
            )

            res = self._transaction_dict_from_pdus(pdus)

        return 200, res

    async def on_timestamp_to_event_request(
        self, origin: str, room_id: str, timestamp: int, direction: str
    ) -> Tuple[int, Dict[str, Any]]:
        """When we receive a federated `/timestamp_to_event` request,
        handle all of the logic for validating and fetching the event.

        Args:
            origin: The server we received the event from
            room_id: Room to fetch the event from
            timestamp: The point in time (inclusive) we should navigate from in
                the given direction to find the closest event.
            direction: ["f"|"b"] to indicate whether we should navigate forward
                or backward from the given timestamp to find the closest event.

        Returns:
            Tuple indicating the response status code and dictionary response
            body including `event_id`.
        """
        async with self._server_linearizer.queue((origin, room_id)):
            origin_host, _ = parse_server_name(origin)
            await self.check_server_matches_acl(origin_host, room_id)

            # We only try to fetch data from the local database
            event_id = await self.store.get_event_id_for_timestamp(
                room_id, timestamp, direction
            )
            if event_id:
                event = await self.store.get_event(
                    event_id, allow_none=False, allow_rejected=False
                )

                return 200, {
                    "event_id": event_id,
                    "origin_server_ts": event.origin_server_ts,
                }

        raise SynapseError(
            404,
            "Unable to find event from %s in direction %s" % (timestamp, direction),
            errcode=Codes.NOT_FOUND,
        )

    async def on_incoming_transaction(
        self,
        origin: str,
        transaction_id: str,
        destination: str,
        transaction_data: JsonDict,
    ) -> Tuple[int, JsonDict]:
        # If we receive a transaction we should make sure that kick off handling
        # any old events in the staging area.
        if not self._started_handling_of_staged_events:
            self._started_handling_of_staged_events = True
            self._handle_old_staged_events()

            # Start a periodic check for old staged events. This is to handle
            # the case where locks time out, e.g. if another process gets killed
            # without dropping its locks.
            self._clock.looping_call(self._handle_old_staged_events, 60 * 1000)

        # keep this as early as possible to make the calculated origin ts as
        # accurate as possible.
        request_time = self._clock.time_msec()

        transaction = Transaction(
            transaction_id=transaction_id,
            destination=destination,
            origin=origin,
            origin_server_ts=transaction_data.get("origin_server_ts"),  # type: ignore[arg-type]
            pdus=transaction_data.get("pdus"),
            edus=transaction_data.get("edus"),
        )

        if not transaction_id:
            raise Exception("Transaction missing transaction_id")

        logger.debug("[%s] Got transaction", transaction_id)

        # Reject malformed transactions early: reject if too many PDUs/EDUs
        if len(transaction.pdus) > 50 or len(transaction.edus) > 100:
            logger.info("Transaction PDU or EDU count too large. Returning 400")
            return 400, {}

        # we only process one transaction from each origin at a time. We need to do
        # this check here, rather than in _on_incoming_transaction_inner so that we
        # don't cache the rejection in _transaction_resp_cache (so that if the txn
        # arrives again later, we can process it).
        current_transaction = self._active_transactions.get(origin)
        if current_transaction and current_transaction != transaction_id:
            logger.warning(
                "Received another txn %s from %s while still processing %s",
                transaction_id,
                origin,
                current_transaction,
            )
            return 429, {
                "errcode": Codes.UNKNOWN,
                "error": "Too many concurrent transactions",
            }

        # CRITICAL SECTION: we must now not await until we populate _active_transactions
        # in _on_incoming_transaction_inner.

        # We wrap in a ResponseCache so that we de-duplicate retried
        # transactions.
        return await self._transaction_resp_cache.wrap(
            (origin, transaction_id),
            self._on_incoming_transaction_inner,
            origin,
            transaction,
            request_time,
        )

    async def _on_incoming_transaction_inner(
        self, origin: str, transaction: Transaction, request_time: int
    ) -> Tuple[int, Dict[str, Any]]:
        # CRITICAL SECTION: the first thing we must do (before awaiting) is
        # add an entry to _active_transactions.
        assert origin not in self._active_transactions
        self._active_transactions[origin] = transaction.transaction_id

        try:
            result = await self._handle_incoming_transaction(
                origin, transaction, request_time
            )
            return result
        finally:
            del self._active_transactions[origin]

    async def _handle_incoming_transaction(
        self, origin: str, transaction: Transaction, request_time: int
    ) -> Tuple[int, Dict[str, Any]]:
        """Process an incoming transaction and return the HTTP response

        Args:
            origin: the server making the request
            transaction: incoming transaction
            request_time: timestamp that the HTTP request arrived at

        Returns:
            HTTP response code and body
        """
        existing_response = await self.transaction_actions.have_responded(
            origin, transaction
        )

        if existing_response:
            logger.debug(
                "[%s] We've already responded to this request",
                transaction.transaction_id,
            )
            return existing_response

        logger.debug("[%s] Transaction is new", transaction.transaction_id)

        # We process PDUs and EDUs in parallel. This is important as we don't
        # want to block things like to device messages from reaching clients
        # behind the potentially expensive handling of PDUs.
        pdu_results, _ = await make_deferred_yieldable(
            gather_results(
                (
                    run_in_background(
                        self._handle_pdus_in_txn, origin, transaction, request_time
                    ),
                    run_in_background(self._handle_edus_in_txn, origin, transaction),
                ),
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        response = {"pdus": pdu_results}

        logger.debug("Returning: %s", str(response))

        await self.transaction_actions.set_response(origin, transaction, 200, response)
        return 200, response

    async def _handle_pdus_in_txn(
        self, origin: str, transaction: Transaction, request_time: int
    ) -> Dict[str, dict]:
        """Process the PDUs in a received transaction.

        Args:
            origin: the server making the request
            transaction: incoming transaction
            request_time: timestamp that the HTTP request arrived at

        Returns:
            A map from event ID of a processed PDU to any errors we should
            report back to the sending server.
        """

        received_pdus_counter.inc(len(transaction.pdus))

        origin_host, _ = parse_server_name(origin)

        pdus_by_room: Dict[str, List[EventBase]] = {}

        newest_pdu_ts = 0

        for p in transaction.pdus:
            # FIXME (richardv): I don't think this works:
            #  https://github.com/matrix-org/synapse/issues/8429
            if "unsigned" in p:
                unsigned = p["unsigned"]
                if "age" in unsigned:
                    p["age"] = unsigned["age"]
            if "age" in p:
                p["age_ts"] = request_time - int(p["age"])
                del p["age"]

            # We try and pull out an event ID so that if later checks fail we
            # can log something sensible. We don't mandate an event ID here in
            # case future event formats get rid of the key.
            possible_event_id = p.get("event_id", "<Unknown>")

            # Now we get the room ID so that we can check that we know the
            # version of the room.
            room_id = p.get("room_id")
            if not room_id:
                logger.info(
                    "Ignoring PDU as does not have a room_id. Event ID: %s",
                    possible_event_id,
                )
                continue

            try:
                room_version = await self.store.get_room_version(room_id)
            except NotFoundError:
                logger.info("Ignoring PDU for unknown room_id: %s", room_id)
                continue
            except UnsupportedRoomVersionError as e:
                # this can happen if support for a given room version is withdrawn,
                # so that we still get events for said room.
                logger.info("Ignoring PDU: %s", e)
                continue

            event = event_from_pdu_json(p, room_version)
            pdus_by_room.setdefault(room_id, []).append(event)

            if event.origin_server_ts > newest_pdu_ts:
                newest_pdu_ts = event.origin_server_ts

        pdu_results = {}

        # we can process different rooms in parallel (which is useful if they
        # require callouts to other servers to fetch missing events), but
        # impose a limit to avoid going too crazy with ram/cpu.

        async def process_pdus_for_room(room_id: str) -> None:
            with nested_logging_context(room_id):
                logger.debug("Processing PDUs for %s", room_id)

                try:
                    await self.check_server_matches_acl(origin_host, room_id)
                except AuthError as e:
                    logger.warning(
                        "Ignoring PDUs for room %s from banned server", room_id
                    )
                    for pdu in pdus_by_room[room_id]:
                        event_id = pdu.event_id
                        pdu_results[event_id] = e.error_dict(self.hs.config)
                    return

                for pdu in pdus_by_room[room_id]:
                    pdu_results[pdu.event_id] = await process_pdu(pdu)

        async def process_pdu(pdu: EventBase) -> JsonDict:
            """
            Processes a pushed PDU sent to us via a `/send` transaction

            Returns:
                JsonDict representing a "PDU Processing Result" that will be bundled up
                with the other processed PDU's in the `/send` transaction and sent back
                to remote homeserver.
            """
            event_id = pdu.event_id
            with nested_logging_context(event_id):
                try:
                    await self._handle_received_pdu(origin, pdu)
                    return {}
                except FederationError as e:
                    logger.warning("Error handling PDU %s: %s", event_id, e)
                    return {"error": str(e)}
                except Exception as e:
                    f = failure.Failure()
                    logger.error(
                        "Failed to handle PDU %s",
                        event_id,
                        exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore
                    )
                    return {"error": str(e)}

        await concurrently_execute(
            process_pdus_for_room, pdus_by_room.keys(), TRANSACTION_CONCURRENCY_LIMIT
        )

        if newest_pdu_ts and origin in self._federation_metrics_domains:
            last_pdu_ts_metric.labels(server_name=origin).set(newest_pdu_ts / 1000)

        return pdu_results

    async def _handle_edus_in_txn(self, origin: str, transaction: Transaction) -> None:
        """Process the EDUs in a received transaction."""

        async def _process_edu(edu_dict: JsonDict) -> None:
            received_edus_counter.inc()

            edu = Edu(
                origin=origin,
                destination=self.server_name,
                edu_type=edu_dict["edu_type"],
                content=edu_dict["content"],
            )
            await self.registry.on_edu(edu.edu_type, origin, edu.content)

        await concurrently_execute(
            _process_edu,
            transaction.edus,
            TRANSACTION_CONCURRENCY_LIMIT,
        )

    async def on_room_state_request(
        self, origin: str, room_id: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        await self._event_auth_handler.assert_host_in_room(room_id, origin)
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)

        # we grab the linearizer to protect ourselves from servers which hammer
        # us. In theory we might already have the response to this query
        # in the cache so we could return it without waiting for the linearizer
        # - but that's non-trivial to get right, and anyway somewhat defeats
        # the point of the linearizer.
        async with self._server_linearizer.queue((origin, room_id)):
            resp = await self._state_resp_cache.wrap(
                (room_id, event_id),
                self._on_context_state_request_compute,
                room_id,
                event_id,
            )

        return 200, resp

    @trace
    @tag_args
    async def on_state_ids_request(
        self, origin: str, room_id: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        if not event_id:
            raise NotImplementedError("Specify an event")

        await self._event_auth_handler.assert_host_in_room(room_id, origin)
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)

        resp = await self._state_ids_resp_cache.wrap(
            (room_id, event_id),
            self._on_state_ids_request_compute,
            room_id,
            event_id,
        )

        return 200, resp

    @trace
    @tag_args
    async def _on_state_ids_request_compute(
        self, room_id: str, event_id: str
    ) -> JsonDict:
        state_ids = await self.handler.get_state_ids_for_pdu(room_id, event_id)
        auth_chain_ids = await self.store.get_auth_chain_ids(room_id, state_ids)
        return {"pdu_ids": state_ids, "auth_chain_ids": list(auth_chain_ids)}

    async def _on_context_state_request_compute(
        self, room_id: str, event_id: str
    ) -> Dict[str, list]:
        pdus: Collection[EventBase]
        event_ids = await self.handler.get_state_ids_for_pdu(room_id, event_id)
        pdus = await self.store.get_events_as_list(event_ids)

        auth_chain = await self.store.get_auth_chain(
            room_id, [pdu.event_id for pdu in pdus]
        )

        return {
            "pdus": [pdu.get_pdu_json() for pdu in pdus],
            "auth_chain": [pdu.get_pdu_json() for pdu in auth_chain],
        }

    async def on_pdu_request(
        self, origin: str, event_id: str
    ) -> Tuple[int, Union[JsonDict, str]]:
        pdu = await self.handler.get_persisted_pdu(origin, event_id)

        if pdu:
            return 200, self._transaction_dict_from_pdus([pdu])
        else:
            return 404, ""

    async def on_query_request(
        self, query_type: str, args: Dict[str, str]
    ) -> Tuple[int, Dict[str, Any]]:
        received_queries_counter.labels(query_type).inc()
        resp = await self.registry.on_query(query_type, args)
        return 200, resp

    async def on_make_join_request(
        self, origin: str, room_id: str, user_id: str, supported_versions: List[str]
    ) -> Dict[str, Any]:
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)

        room_version = await self.store.get_room_version_id(room_id)
        if room_version not in supported_versions:
            logger.warning(
                "Room version %s not in %s", room_version, supported_versions
            )
            raise IncompatibleRoomVersionError(room_version=room_version)

        # Refuse the request if that room has seen too many joins recently.
        # This is in addition to the HS-level rate limiting applied by
        # BaseFederationServlet.
        # type-ignore: mypy doesn't seem able to deduce the type of the limiter(!?)
        await self._room_member_handler._join_rate_per_room_limiter.ratelimit(  # type: ignore[has-type]
            requester=None,
            key=room_id,
            update=False,
        )
        pdu = await self.handler.on_make_join_request(origin, room_id, user_id)
        return {"event": pdu.get_templated_pdu_json(), "room_version": room_version}

    async def on_invite_request(
        self, origin: str, content: JsonDict, room_version_id: str
    ) -> Dict[str, Any]:
        room_version = KNOWN_ROOM_VERSIONS.get(room_version_id)
        if not room_version:
            raise SynapseError(
                400,
                "Homeserver does not support this room version",
                Codes.UNSUPPORTED_ROOM_VERSION,
            )

        pdu = event_from_pdu_json(content, room_version)
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, pdu.room_id)
        try:
            pdu = await self._check_sigs_and_hash(room_version, pdu)
        except InvalidEventSignatureError as e:
            errmsg = f"event id {pdu.event_id}: {e}"
            logger.warning("%s", errmsg)
            raise SynapseError(403, errmsg, Codes.FORBIDDEN)
        ret_pdu = await self.handler.on_invite_request(origin, pdu, room_version)
        time_now = self._clock.time_msec()
        return {"event": ret_pdu.get_pdu_json(time_now)}

    async def on_send_join_request(
        self,
        origin: str,
        content: JsonDict,
        room_id: str,
        caller_supports_partial_state: bool = False,
    ) -> Dict[str, Any]:
        await self._room_member_handler._join_rate_per_room_limiter.ratelimit(  # type: ignore[has-type]
            requester=None,
            key=room_id,
            update=False,
        )

        event, context = await self._on_send_membership_event(
            origin, content, Membership.JOIN, room_id
        )

        prev_state_ids = await context.get_prev_state_ids()

        state_event_ids: Collection[str]
        servers_in_room: Optional[Collection[str]]
        if caller_supports_partial_state:
            state_event_ids = _get_event_ids_for_partial_state_join(
                event, prev_state_ids
            )
            servers_in_room = await self.state.get_hosts_in_room_at_events(
                room_id, event_ids=event.prev_event_ids()
            )
        else:
            state_event_ids = prev_state_ids.values()
            servers_in_room = None

        auth_chain_event_ids = await self.store.get_auth_chain_ids(
            room_id, state_event_ids
        )

        # if the caller has opted in, we can omit any auth_chain events which are
        # already in state_event_ids
        if caller_supports_partial_state:
            auth_chain_event_ids.difference_update(state_event_ids)

        auth_chain_events = await self.store.get_events_as_list(auth_chain_event_ids)
        state_events = await self.store.get_events_as_list(state_event_ids)

        # we try to do all the async stuff before this point, so that time_now is as
        # accurate as possible.
        time_now = self._clock.time_msec()
        event_json = event.get_pdu_json(time_now)
        resp = {
            "event": event_json,
            "state": [p.get_pdu_json(time_now) for p in state_events],
            "auth_chain": [p.get_pdu_json(time_now) for p in auth_chain_events],
            "org.matrix.msc3706.partial_state": caller_supports_partial_state,
        }

        if servers_in_room is not None:
            resp["org.matrix.msc3706.servers_in_room"] = list(servers_in_room)

        return resp

    async def on_make_leave_request(
        self, origin: str, room_id: str, user_id: str
    ) -> Dict[str, Any]:
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)
        pdu = await self.handler.on_make_leave_request(origin, room_id, user_id)

        room_version = await self.store.get_room_version_id(room_id)

        return {"event": pdu.get_templated_pdu_json(), "room_version": room_version}

    async def on_send_leave_request(
        self, origin: str, content: JsonDict, room_id: str
    ) -> dict:
        logger.debug("on_send_leave_request: content: %s", content)
        await self._on_send_membership_event(origin, content, Membership.LEAVE, room_id)
        return {}

    async def on_make_knock_request(
        self, origin: str, room_id: str, user_id: str, supported_versions: List[str]
    ) -> JsonDict:
        """We've received a /make_knock/ request, so we create a partial knock
        event for the room and hand that back, along with the room version, to the knocking
        homeserver. We do *not* persist or process this event until the other server has
        signed it and sent it back.

        Args:
            origin: The (verified) server name of the requesting server.
            room_id: The room to create the knock event in.
            user_id: The user to create the knock for.
            supported_versions: The room versions supported by the requesting server.

        Returns:
            The partial knock event.
        """
        origin_host, _ = parse_server_name(origin)

        if await self.store.is_partial_state_room(room_id):
            # Before we do anything: check if the room is partial-stated.
            # Note that at the time this check was added, `on_make_knock_request` would
            # block due to https://github.com/matrix-org/synapse/issues/12997.
            raise SynapseError(
                404,
                "Unable to handle /make_knock right now; this server is not fully joined.",
                errcode=Codes.NOT_FOUND,
            )

        await self.check_server_matches_acl(origin_host, room_id)

        room_version = await self.store.get_room_version(room_id)

        # Check that this room version is supported by the remote homeserver
        if room_version.identifier not in supported_versions:
            logger.warning(
                "Room version %s not in %s", room_version.identifier, supported_versions
            )
            raise IncompatibleRoomVersionError(room_version=room_version.identifier)

        # Check that this room supports knocking as defined by its room version
        if not room_version.msc2403_knocking:
            raise SynapseError(
                403,
                "This room version does not support knocking",
                errcode=Codes.FORBIDDEN,
            )

        pdu = await self.handler.on_make_knock_request(origin, room_id, user_id)
        return {
            "event": pdu.get_templated_pdu_json(),
            "room_version": room_version.identifier,
        }

    async def on_send_knock_request(
        self,
        origin: str,
        content: JsonDict,
        room_id: str,
    ) -> Dict[str, List[JsonDict]]:
        """
        We have received a knock event for a room. Verify and send the event into the room
        on the knocking homeserver's behalf. Then reply with some stripped state from the
        room for the knockee.

        Args:
            origin: The remote homeserver of the knocking user.
            content: The content of the request.
            room_id: The ID of the room to knock on.

        Returns:
            The stripped room state.
        """
        _, context = await self._on_send_membership_event(
            origin, content, Membership.KNOCK, room_id
        )

        # Retrieve stripped state events from the room and send them back to the remote
        # server. This will allow the remote server's clients to display information
        # related to the room while the knock request is pending.
        stripped_room_state = (
            await self.store.get_stripped_room_state_from_event_context(
                context, self._room_prejoin_state_types
            )
        )
        return {
            "knock_room_state": stripped_room_state,
            # Since v1.37, Synapse incorrectly used "knock_state_events" for this field.
            # Thus, we also populate a 'knock_state_events' with the same content to
            # support old instances.
            # See https://github.com/matrix-org/synapse/issues/14088.
            "knock_state_events": stripped_room_state,
        }

    async def _on_send_membership_event(
        self, origin: str, content: JsonDict, membership_type: str, room_id: str
    ) -> Tuple[EventBase, EventContext]:
        """Handle an on_send_{join,leave,knock} request

        Does some preliminary validation before passing the request on to the
        federation handler.

        Args:
            origin: The (authenticated) requesting server
            content: The body of the send_* request - a complete membership event
            membership_type: The expected membership type (join or leave, depending
                on the endpoint)
            room_id: The room_id from the request, to be validated against the room_id
                in the event

        Returns:
            The event and context of the event after inserting it into the room graph.

        Raises:
            SynapseError if there is a problem with the request, including things like
               the room_id not matching or the event not being authorized.
        """
        assert_params_in_dict(content, ["room_id"])
        if content["room_id"] != room_id:
            raise SynapseError(
                400,
                "Room ID in body does not match that in request path",
                Codes.BAD_JSON,
            )

        # Note that get_room_version throws if the room does not exist here.
        room_version = await self.store.get_room_version(room_id)

        if await self.store.is_partial_state_room(room_id):
            # If our server is still only partially joined, we can't give a complete
            # response to /send_join, /send_knock or /send_leave.
            # This is because we will not be able to provide the server list (for partial
            # joins) or the full state (for full joins).
            # Return a 404 as we would if we weren't in the room at all.
            logger.info(
                f"Rejecting /send_{membership_type} to %s because it's a partial state room",
                room_id,
            )
            raise SynapseError(
                404,
                f"Unable to handle /send_{membership_type} right now; this server is not fully joined.",
                errcode=Codes.NOT_FOUND,
            )

        if membership_type == Membership.KNOCK and not room_version.msc2403_knocking:
            raise SynapseError(
                403,
                "This room version does not support knocking",
                errcode=Codes.FORBIDDEN,
            )

        event = event_from_pdu_json(content, room_version)

        if event.type != EventTypes.Member or not event.is_state():
            raise SynapseError(400, "Not an m.room.member event", Codes.BAD_JSON)

        if event.content.get("membership") != membership_type:
            raise SynapseError(400, "Not a %s event" % membership_type, Codes.BAD_JSON)

        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, event.room_id)

        logger.debug("_on_send_membership_event: pdu sigs: %s", event.signatures)

        # Sign the event since we're vouching on behalf of the remote server that
        # the event is valid to be sent into the room. Currently this is only done
        # if the user is being joined via restricted join rules.
        if (
            room_version.msc3083_join_rules
            and event.membership == Membership.JOIN
            and EventContentFields.AUTHORISING_USER in event.content
        ):
            # We can only authorise our own users.
            authorising_server = get_domain_from_id(
                event.content[EventContentFields.AUTHORISING_USER]
            )
            if authorising_server != self.server_name:
                raise SynapseError(
                    400,
                    f"Cannot authorise request from resident server: {authorising_server}",
                )

            event.signatures.update(
                compute_event_signature(
                    room_version,
                    event.get_pdu_json(),
                    self.hs.hostname,
                    self.hs.signing_key,
                )
            )

        try:
            event = await self._check_sigs_and_hash(room_version, event)
        except InvalidEventSignatureError as e:
            errmsg = f"event id {event.event_id}: {e}"
            logger.warning("%s", errmsg)
            raise SynapseError(403, errmsg, Codes.FORBIDDEN)

        try:
            return await self._federation_event_handler.on_send_membership_event(
                origin, event
            )
        except PartialStateConflictError:
            # The room was un-partial stated while we were persisting the event.
            # Try once more, with full state this time.
            logger.info(
                "Room %s was un-partial stated during `on_send_membership_event`, trying again.",
                room_id,
            )
            return await self._federation_event_handler.on_send_membership_event(
                origin, event
            )

    async def on_event_auth(
        self, origin: str, room_id: str, event_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        async with self._server_linearizer.queue((origin, room_id)):
            await self._event_auth_handler.assert_host_in_room(room_id, origin)
            origin_host, _ = parse_server_name(origin)
            await self.check_server_matches_acl(origin_host, room_id)

            time_now = self._clock.time_msec()
            auth_pdus = await self.handler.on_event_auth(event_id)
            res = {"auth_chain": [a.get_pdu_json(time_now) for a in auth_pdus]}
        return 200, res

    async def on_query_client_keys(
        self, origin: str, content: Dict[str, str]
    ) -> Tuple[int, Dict[str, Any]]:
        return await self.on_query_request("client_keys", content)

    async def on_query_user_devices(
        self, origin: str, user_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        keys = await self.device_handler.on_federation_query_user_devices(user_id)
        return 200, keys

    @trace
    async def on_claim_client_keys(
        self, origin: str, content: JsonDict
    ) -> Dict[str, Any]:
        query = []
        for user_id, device_keys in content.get("one_time_keys", {}).items():
            for device_id, algorithm in device_keys.items():
                query.append((user_id, device_id, algorithm))

        log_kv({"message": "Claiming one time keys.", "user, device pairs": query})
        results = await self.store.claim_e2e_one_time_keys(query)

        json_result: Dict[str, Dict[str, dict]] = {}
        for user_id, device_keys in results.items():
            for device_id, keys in device_keys.items():
                for key_id, json_str in keys.items():
                    json_result.setdefault(user_id, {})[device_id] = {
                        key_id: json_decoder.decode(json_str)
                    }

        logger.info(
            "Claimed one-time-keys: %s",
            ",".join(
                (
                    "%s for %s:%s" % (key_id, user_id, device_id)
                    for user_id, user_keys in json_result.items()
                    for device_id, device_keys in user_keys.items()
                    for key_id, _ in device_keys.items()
                )
            ),
        )

        return {"one_time_keys": json_result}

    async def on_get_missing_events(
        self,
        origin: str,
        room_id: str,
        earliest_events: List[str],
        latest_events: List[str],
        limit: int,
    ) -> Dict[str, list]:
        async with self._server_linearizer.queue((origin, room_id)):
            origin_host, _ = parse_server_name(origin)
            await self.check_server_matches_acl(origin_host, room_id)

            logger.debug(
                "on_get_missing_events: earliest_events: %r, latest_events: %r,"
                " limit: %d",
                earliest_events,
                latest_events,
                limit,
            )

            missing_events = await self.handler.on_get_missing_events(
                origin, room_id, earliest_events, latest_events, limit
            )

            if len(missing_events) < 5:
                logger.debug(
                    "Returning %d events: %r", len(missing_events), missing_events
                )
            else:
                logger.debug("Returning %d events", len(missing_events))

            time_now = self._clock.time_msec()

        return {"events": [ev.get_pdu_json(time_now) for ev in missing_events]}

    async def on_openid_userinfo(self, token: str) -> Optional[str]:
        ts_now_ms = self._clock.time_msec()
        return await self.store.get_user_id_for_open_id_token(token, ts_now_ms)

    def _transaction_dict_from_pdus(self, pdu_list: List[EventBase]) -> JsonDict:
        """Returns a new Transaction containing the given PDUs suitable for
        transmission.
        """
        time_now = self._clock.time_msec()
        pdus = [p.get_pdu_json(time_now) for p in pdu_list]
        return Transaction(
            # Just need a dummy transaction ID and destination since it won't be used.
            transaction_id="",
            origin=self.server_name,
            pdus=pdus,
            origin_server_ts=int(time_now),
            destination="",
        ).get_dict()

    async def _handle_received_pdu(self, origin: str, pdu: EventBase) -> None:
        """Process a PDU received in a federation /send/ transaction.

        If the event is invalid, then this method throws a FederationError.
        (The error will then be logged and sent back to the sender (which
        probably won't do anything with it), and other events in the
        transaction will be processed as normal).

        It is likely that we'll then receive other events which refer to
        this rejected_event in their prev_events, etc.  When that happens,
        we'll attempt to fetch the rejected event again, which will presumably
        fail, so those second-generation events will also get rejected.

        Eventually, we get to the point where there are more than 10 events
        between any new events and the original rejected event. Since we
        only try to backfill 10 events deep on received pdu, we then accept the
        new event, possibly introducing a discontinuity in the DAG, with new
        forward extremities, so normal service is approximately returned,
        until we try to backfill across the discontinuity.

        Args:
            origin: server which sent the pdu
            pdu: received pdu

        Raises: FederationError if the signatures / hash do not match, or
            if the event was unacceptable for any other reason (eg, too large,
            too many prev_events, couldn't find the prev_events)
        """

        # We've already checked that we know the room version by this point
        room_version = await self.store.get_room_version(pdu.room_id)

        # Check signature.
        try:
            pdu = await self._check_sigs_and_hash(room_version, pdu)
        except InvalidEventSignatureError as e:
            logger.warning("event id %s: %s", pdu.event_id, e)
            raise FederationError("ERROR", 403, str(e), affected=pdu.event_id)

        if await self._spam_checker.should_drop_federated_event(pdu):
            logger.warning(
                "Unstaged federated event contains spam, dropping %s", pdu.event_id
            )
            return

        # Add the event to our staging area
        await self.store.insert_received_event_to_staging(origin, pdu)

        # Try and acquire the processing lock for the room, if we get it start a
        # background process for handling the events in the room.
        lock = await self.store.try_acquire_lock(
            _INBOUND_EVENT_HANDLING_LOCK_NAME, pdu.room_id
        )
        if lock:
            self._process_incoming_pdus_in_room_inner(
                pdu.room_id, room_version, lock, origin, pdu
            )

    async def _get_next_nonspam_staged_event_for_room(
        self, room_id: str, room_version: RoomVersion
    ) -> Optional[Tuple[str, EventBase]]:
        """Fetch the first non-spam event from staging queue.

        Args:
            room_id: the room to fetch the first non-spam event in.
            room_version: the version of the room.

        Returns:
            The first non-spam event in that room.
        """

        while True:
            # We need to do this check outside the lock to avoid a race between
            # a new event being inserted by another instance and it attempting
            # to acquire the lock.
            next = await self.store.get_next_staged_event_for_room(
                room_id, room_version
            )

            if next is None:
                return None

            origin, event = next

            if await self._spam_checker.should_drop_federated_event(event):
                logger.warning(
                    "Staged federated event contains spam, dropping %s",
                    event.event_id,
                )
                continue

            return next

    @wrap_as_background_process("_process_incoming_pdus_in_room_inner")
    async def _process_incoming_pdus_in_room_inner(
        self,
        room_id: str,
        room_version: RoomVersion,
        lock: Lock,
        latest_origin: Optional[str] = None,
        latest_event: Optional[EventBase] = None,
    ) -> None:
        """Process events in the staging area for the given room.

        The latest_origin and latest_event args are the latest origin and event
        received (or None to simply pull the next event from the database).
        """

        # The common path is for the event we just received be the only event in
        # the room, so instead of pulling the event out of the DB and parsing
        # the event we just pull out the next event ID and check if that matches.
        if latest_event is not None and latest_origin is not None:
            result = await self.store.get_next_staged_event_id_for_room(room_id)
            if result is None:
                latest_origin = None
                latest_event = None
            else:
                next_origin, next_event_id = result
                if (
                    next_origin != latest_origin
                    or next_event_id != latest_event.event_id
                ):
                    latest_origin = None
                    latest_event = None

        if latest_origin is None or latest_event is None:
            next = await self.store.get_next_staged_event_for_room(
                room_id, room_version
            )
            if not next:
                await lock.release()
                return

            origin, event = next
        else:
            origin = latest_origin
            event = latest_event

        # We loop round until there are no more events in the room in the
        # staging area, or we fail to get the lock (which means another process
        # has started processing).
        while True:
            async with lock:
                logger.info("handling received PDU in room %s: %s", room_id, event)
                try:
                    with nested_logging_context(event.event_id):
                        await self._federation_event_handler.on_receive_pdu(
                            origin, event
                        )
                except FederationError as e:
                    # XXX: Ideally we'd inform the remote we failed to process
                    # the event, but we can't return an error in the transaction
                    # response (as we've already responded).
                    logger.warning("Error handling PDU %s: %s", event.event_id, e)
                except Exception:
                    f = failure.Failure()
                    logger.error(
                        "Failed to handle PDU %s",
                        event.event_id,
                        exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore
                    )

                received_ts = await self.store.remove_received_event_from_staging(
                    origin, event.event_id
                )
                if received_ts is not None:
                    pdu_process_time.observe(
                        (self._clock.time_msec() - received_ts) / 1000
                    )

            next = await self._get_next_nonspam_staged_event_for_room(
                room_id, room_version
            )

            if not next:
                break

            origin, event = next

            # Prune the event queue if it's getting large.
            #
            # We do this *after* handling the first event as the common case is
            # that the queue is empty (/has the single event in), and so there's
            # no need to do this check.
            pruned = await self.store.prune_staged_events_in_room(room_id, room_version)
            if pruned:
                # If we have pruned the queue check we need to refetch the next
                # event to handle.
                next = await self.store.get_next_staged_event_for_room(
                    room_id, room_version
                )
                if not next:
                    break

                origin, event = next

            new_lock = await self.store.try_acquire_lock(
                _INBOUND_EVENT_HANDLING_LOCK_NAME, room_id
            )
            if not new_lock:
                return
            lock = new_lock

    def __str__(self) -> str:
        return "<ReplicationLayer(%s)>" % self.server_name

    async def exchange_third_party_invite(
        self, sender_user_id: str, target_user_id: str, room_id: str, signed: Dict
    ) -> None:
        await self.handler.exchange_third_party_invite(
            sender_user_id, target_user_id, room_id, signed
        )

    async def on_exchange_third_party_invite_request(self, event_dict: Dict) -> None:
        await self.handler.on_exchange_third_party_invite_request(event_dict)

    async def check_server_matches_acl(self, server_name: str, room_id: str) -> None:
        """Check if the given server is allowed by the server ACLs in the room

        Args:
            server_name: name of server, *without any port part*
            room_id: ID of the room to check

        Raises:
            AuthError if the server does not match the ACL
        """
        acl_event = await self._storage_controllers.state.get_current_state_event(
            room_id, EventTypes.ServerACL, ""
        )
        if not acl_event or server_matches_acl_event(server_name, acl_event):
            return

        raise AuthError(code=403, msg="Server is banned from room")


def server_matches_acl_event(server_name: str, acl_event: EventBase) -> bool:
    """Check if the given server is allowed by the ACL event

    Args:
        server_name: name of server, without any port part
        acl_event: m.room.server_acl event

    Returns:
        True if this server is allowed by the ACLs
    """
    logger.debug("Checking %s against acl %s", server_name, acl_event.content)

    # first of all, check if literal IPs are blocked, and if so, whether the
    # server name is a literal IP
    allow_ip_literals = acl_event.content.get("allow_ip_literals", True)
    if not isinstance(allow_ip_literals, bool):
        logger.warning("Ignoring non-bool allow_ip_literals flag")
        allow_ip_literals = True
    if not allow_ip_literals:
        # check for ipv6 literals. These start with '['.
        if server_name[0] == "[":
            return False

        # check for ipv4 literals. We can just lift the routine from twisted.
        if isIPAddress(server_name):
            return False

    # next,  check the deny list
    deny = acl_event.content.get("deny", [])
    if not isinstance(deny, (list, tuple)):
        logger.warning("Ignoring non-list deny ACL %s", deny)
        deny = []
    for e in deny:
        if _acl_entry_matches(server_name, e):
            # logger.info("%s matched deny rule %s", server_name, e)
            return False

    # then the allow list.
    allow = acl_event.content.get("allow", [])
    if not isinstance(allow, (list, tuple)):
        logger.warning("Ignoring non-list allow ACL %s", allow)
        allow = []
    for e in allow:
        if _acl_entry_matches(server_name, e):
            # logger.info("%s matched allow rule %s", server_name, e)
            return True

    # everything else should be rejected.
    # logger.info("%s fell through", server_name)
    return False


def _acl_entry_matches(server_name: str, acl_entry: Any) -> bool:
    if not isinstance(acl_entry, str):
        logger.warning(
            "Ignoring non-str ACL entry '%s' (is %s)", acl_entry, type(acl_entry)
        )
        return False
    regex = glob_to_regex(acl_entry)
    return bool(regex.match(server_name))


class FederationHandlerRegistry:
    """Allows classes to register themselves as handlers for a given EDU or
    query type for incoming federation traffic.
    """

    def __init__(self, hs: "HomeServer"):
        self.config = hs.config
        self.clock = hs.get_clock()
        self._instance_name = hs.get_instance_name()

        # These are safe to load in monolith mode, but will explode if we try
        # and use them. However we have guards before we use them to ensure that
        # we don't route to ourselves, and in monolith mode that will always be
        # the case.
        self._get_query_client = ReplicationGetQueryRestServlet.make_client(hs)
        self._send_edu = ReplicationFederationSendEduRestServlet.make_client(hs)

        self.edu_handlers: Dict[str, Callable[[str, dict], Awaitable[None]]] = {}
        self.query_handlers: Dict[str, Callable[[dict], Awaitable[JsonDict]]] = {}

        # Map from type to instance names that we should route EDU handling to.
        # We randomly choose one instance from the list to route to for each new
        # EDU received.
        self._edu_type_to_instance: Dict[str, List[str]] = {}

    def register_edu_handler(
        self, edu_type: str, handler: Callable[[str, JsonDict], Awaitable[None]]
    ) -> None:
        """Sets the handler callable that will be used to handle an incoming
        federation EDU of the given type.

        Args:
            edu_type: The type of the incoming EDU to register handler for
            handler: A callable invoked on incoming EDU
                of the given type. The arguments are the origin server name and
                the EDU contents.
        """
        if edu_type in self.edu_handlers:
            raise KeyError("Already have an EDU handler for %s" % (edu_type,))

        logger.info("Registering federation EDU handler for %r", edu_type)

        self.edu_handlers[edu_type] = handler

    def register_query_handler(
        self, query_type: str, handler: Callable[[dict], Awaitable[JsonDict]]
    ) -> None:
        """Sets the handler callable that will be used to handle an incoming
        federation query of the given type.

        Args:
            query_type: Category name of the query, which should match
                the string used by make_query.
            handler: Invoked to handle
                incoming queries of this type. The return will be yielded
                on and the result used as the response to the query request.
        """
        if query_type in self.query_handlers:
            raise KeyError("Already have a Query handler for %s" % (query_type,))

        logger.info("Registering federation query handler for %r", query_type)

        self.query_handlers[query_type] = handler

    def register_instances_for_edu(
        self, edu_type: str, instance_names: List[str]
    ) -> None:
        """Register that the EDU handler is on multiple instances."""
        self._edu_type_to_instance[edu_type] = instance_names

    async def on_edu(self, edu_type: str, origin: str, content: dict) -> None:
        if not self.config.server.use_presence and edu_type == EduTypes.PRESENCE:
            return

        # Check if we have a handler on this instance
        handler = self.edu_handlers.get(edu_type)
        if handler:
            with start_active_span_from_edu(content, "handle_edu"):
                try:
                    await handler(origin, content)
                except SynapseError as e:
                    logger.info("Failed to handle edu %r: %r", edu_type, e)
                except Exception:
                    logger.exception("Failed to handle edu %r", edu_type)
            return

        # Check if we can route it somewhere else that isn't us
        instances = self._edu_type_to_instance.get(edu_type, ["master"])
        if self._instance_name not in instances:
            # Pick an instance randomly so that we don't overload one.
            route_to = random.choice(instances)

            try:
                await self._send_edu(
                    instance_name=route_to,
                    edu_type=edu_type,
                    origin=origin,
                    content=content,
                )
            except SynapseError as e:
                logger.info("Failed to handle edu %r: %r", edu_type, e)
            except Exception:
                logger.exception("Failed to handle edu %r", edu_type)
            return

        # Oh well, let's just log and move on.
        logger.warning("No handler registered for EDU type %s", edu_type)

    async def on_query(self, query_type: str, args: dict) -> JsonDict:
        handler = self.query_handlers.get(query_type)
        if handler:
            return await handler(args)

        # Check if we can route it somewhere else that isn't us
        if self._instance_name == "master":
            return await self._get_query_client(query_type=query_type, args=args)

        # Uh oh, no handler! Let's raise an exception so the request returns an
        # error.
        logger.warning("No handler registered for query type %s", query_type)
        raise NotFoundError("No handler for Query type '%s'" % (query_type,))


def _get_event_ids_for_partial_state_join(
    join_event: EventBase,
    prev_state_ids: StateMap[str],
) -> Collection[str]:
    """Calculate state to be retuned in a partial_state send_join

    Args:
        join_event: the join event being send_joined
        prev_state_ids: the event ids of the state before the join

    Returns:
        the event ids to be returned
    """

    # return all non-member events
    state_event_ids = {
        event_id
        for (event_type, state_key), event_id in prev_state_ids.items()
        if event_type != EventTypes.Member
    }

    # we also need the current state of the current user (it's going to
    # be an auth event for the new join, so we may as well return it)
    current_membership_event_id = prev_state_ids.get(
        (EventTypes.Member, join_event.state_key)
    )
    if current_membership_event_id is not None:
        state_event_ids.add(current_membership_event_id)

    # TODO: return a few more members:
    #   - those with invites
    #   - those that are kicked? / banned

    return state_event_ids
