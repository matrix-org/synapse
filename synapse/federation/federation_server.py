# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2019 Matrix.org Federation C.I.C
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
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Match,
    Optional,
    Tuple,
    Union,
)

from prometheus_client import Counter, Gauge, Histogram

from twisted.internet import defer
from twisted.internet.abstract import isIPAddress
from twisted.python import failure

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    FederationError,
    IncompatibleRoomVersionError,
    NotFoundError,
    SynapseError,
    UnsupportedRoomVersionError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import EventBase
from synapse.federation.federation_base import FederationBase, event_from_pdu_json
from synapse.federation.persistence import TransactionActions
from synapse.federation.units import Edu, Transaction
from synapse.http.endpoint import parse_server_name
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    run_in_background,
)
from synapse.logging.opentracing import log_kv, start_active_span_from_edu, trace
from synapse.logging.utils import log_function
from synapse.replication.http.federation import (
    ReplicationFederationSendEduRestServlet,
    ReplicationGetQueryRestServlet,
)
from synapse.types import JsonDict, get_domain_from_id
from synapse.util import glob_to_regex, json_decoder, unwrapFirstError
from synapse.util.async_helpers import Linearizer, concurrently_execute
from synapse.util.caches.response_cache import ResponseCache

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
    "synapse_federation_server_pdu_process_time", "Time taken to process an event",
)


last_pdu_age_metric = Gauge(
    "synapse_federation_last_received_pdu_age",
    "The age (in seconds) of the last PDU successfully received from the given domain",
    labelnames=("server_name",),
)


class FederationServer(FederationBase):
    def __init__(self, hs):
        super().__init__(hs)

        self.auth = hs.get_auth()
        self.handler = hs.get_handlers().federation_handler
        self.state = hs.get_state_handler()

        self.device_handler = hs.get_device_handler()
        self._federation_ratelimiter = hs.get_federation_ratelimiter()

        self._server_linearizer = Linearizer("fed_server")
        self._transaction_linearizer = Linearizer("fed_txn_handler")

        # We cache results for transaction with the same ID
        self._transaction_resp_cache = ResponseCache(
            hs, "fed_txn_handler", timeout_ms=30000
        )

        self.transaction_actions = TransactionActions(self.store)

        self.registry = hs.get_federation_registry()

        # We cache responses to state queries, as they take a while and often
        # come in waves.
        self._state_resp_cache = ResponseCache(hs, "state_resp", timeout_ms=30000)
        self._state_ids_resp_cache = ResponseCache(
            hs, "state_ids_resp", timeout_ms=30000
        )

        self._federation_metrics_domains = (
            hs.get_config().federation.federation_metrics_domains
        )

    async def on_backfill_request(
        self, origin: str, room_id: str, versions: List[str], limit: int
    ) -> Tuple[int, Dict[str, Any]]:
        with (await self._server_linearizer.queue((origin, room_id))):
            origin_host, _ = parse_server_name(origin)
            await self.check_server_matches_acl(origin_host, room_id)

            pdus = await self.handler.on_backfill_request(
                origin, room_id, versions, limit
            )

            res = self._transaction_from_pdus(pdus).get_dict()

        return 200, res

    async def on_incoming_transaction(
        self, origin: str, transaction_data: JsonDict
    ) -> Tuple[int, Dict[str, Any]]:
        # keep this as early as possible to make the calculated origin ts as
        # accurate as possible.
        request_time = self._clock.time_msec()

        transaction = Transaction(**transaction_data)
        transaction_id = transaction.transaction_id  # type: ignore

        if not transaction_id:
            raise Exception("Transaction missing transaction_id")

        logger.debug("[%s] Got transaction", transaction_id)

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
        # Use a linearizer to ensure that transactions from a remote are
        # processed in order.
        with await self._transaction_linearizer.queue(origin):
            # We rate limit here *after* we've queued up the incoming requests,
            # so that we don't fill up the ratelimiter with blocked requests.
            #
            # This is important as the ratelimiter allows N concurrent requests
            # at a time, and only starts ratelimiting if there are more requests
            # than that being processed at a time. If we queued up requests in
            # the linearizer/response cache *after* the ratelimiting then those
            # queued up requests would count as part of the allowed limit of N
            # concurrent requests.
            with self._federation_ratelimiter.ratelimit(origin) as d:
                await d

                result = await self._handle_incoming_transaction(
                    origin, transaction, request_time
                )

        return result

    async def _handle_incoming_transaction(
        self, origin: str, transaction: Transaction, request_time: int
    ) -> Tuple[int, Dict[str, Any]]:
        """ Process an incoming transaction and return the HTTP response

        Args:
            origin: the server making the request
            transaction: incoming transaction
            request_time: timestamp that the HTTP request arrived at

        Returns:
            HTTP response code and body
        """
        response = await self.transaction_actions.have_responded(origin, transaction)

        if response:
            logger.debug(
                "[%s] We've already responded to this request",
                transaction.transaction_id,  # type: ignore
            )
            return response

        logger.debug("[%s] Transaction is new", transaction.transaction_id)  # type: ignore

        # Reject if PDU count > 50 or EDU count > 100
        if len(transaction.pdus) > 50 or (  # type: ignore
            hasattr(transaction, "edus") and len(transaction.edus) > 100  # type: ignore
        ):

            logger.info("Transaction PDU or EDU count too large. Returning 400")

            response = {}
            await self.transaction_actions.set_response(
                origin, transaction, 400, response
            )
            return 400, response

        # We process PDUs and EDUs in parallel. This is important as we don't
        # want to block things like to device messages from reaching clients
        # behind the potentially expensive handling of PDUs.
        pdu_results, _ = await make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self._handle_pdus_in_txn, origin, transaction, request_time
                    ),
                    run_in_background(self._handle_edus_in_txn, origin, transaction),
                ],
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

        received_pdus_counter.inc(len(transaction.pdus))  # type: ignore

        origin_host, _ = parse_server_name(origin)

        pdus_by_room = {}  # type: Dict[str, List[EventBase]]

        newest_pdu_ts = 0

        for p in transaction.pdus:  # type: ignore
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

        async def process_pdus_for_room(room_id: str):
            logger.debug("Processing PDUs for %s", room_id)
            try:
                await self.check_server_matches_acl(origin_host, room_id)
            except AuthError as e:
                logger.warning("Ignoring PDUs for room %s from banned server", room_id)
                for pdu in pdus_by_room[room_id]:
                    event_id = pdu.event_id
                    pdu_results[event_id] = e.error_dict()
                return

            for pdu in pdus_by_room[room_id]:
                event_id = pdu.event_id
                with pdu_process_time.time():
                    with nested_logging_context(event_id):
                        try:
                            await self._handle_received_pdu(origin, pdu)
                            pdu_results[event_id] = {}
                        except FederationError as e:
                            logger.warning("Error handling PDU %s: %s", event_id, e)
                            pdu_results[event_id] = {"error": str(e)}
                        except Exception as e:
                            f = failure.Failure()
                            pdu_results[event_id] = {"error": str(e)}
                            logger.error(
                                "Failed to handle PDU %s",
                                event_id,
                                exc_info=(f.type, f.value, f.getTracebackObject()),
                            )

        await concurrently_execute(
            process_pdus_for_room, pdus_by_room.keys(), TRANSACTION_CONCURRENCY_LIMIT
        )

        if newest_pdu_ts and origin in self._federation_metrics_domains:
            newest_pdu_age = self._clock.time_msec() - newest_pdu_ts
            last_pdu_age_metric.labels(server_name=origin).set(newest_pdu_age / 1000)

        return pdu_results

    async def _handle_edus_in_txn(self, origin: str, transaction: Transaction):
        """Process the EDUs in a received transaction.
        """

        async def _process_edu(edu_dict):
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
            getattr(transaction, "edus", []),
            TRANSACTION_CONCURRENCY_LIMIT,
        )

    async def on_context_state_request(
        self, origin: str, room_id: str, event_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)

        in_room = await self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        # we grab the linearizer to protect ourselves from servers which hammer
        # us. In theory we might already have the response to this query
        # in the cache so we could return it without waiting for the linearizer
        # - but that's non-trivial to get right, and anyway somewhat defeats
        # the point of the linearizer.
        with (await self._server_linearizer.queue((origin, room_id))):
            resp = dict(
                await self._state_resp_cache.wrap(
                    (room_id, event_id),
                    self._on_context_state_request_compute,
                    room_id,
                    event_id,
                )
            )

        room_version = await self.store.get_room_version_id(room_id)
        resp["room_version"] = room_version

        return 200, resp

    async def on_state_ids_request(
        self, origin: str, room_id: str, event_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        if not event_id:
            raise NotImplementedError("Specify an event")

        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)

        in_room = await self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        resp = await self._state_ids_resp_cache.wrap(
            (room_id, event_id), self._on_state_ids_request_compute, room_id, event_id,
        )

        return 200, resp

    async def _on_state_ids_request_compute(self, room_id, event_id):
        state_ids = await self.handler.get_state_ids_for_pdu(room_id, event_id)
        auth_chain_ids = await self.store.get_auth_chain_ids(state_ids)
        return {"pdu_ids": state_ids, "auth_chain_ids": auth_chain_ids}

    async def _on_context_state_request_compute(
        self, room_id: str, event_id: str
    ) -> Dict[str, list]:
        if event_id:
            pdus = await self.handler.get_state_for_pdu(room_id, event_id)
        else:
            pdus = (await self.state.get_current_state(room_id)).values()

        auth_chain = await self.store.get_auth_chain([pdu.event_id for pdu in pdus])

        return {
            "pdus": [pdu.get_pdu_json() for pdu in pdus],
            "auth_chain": [pdu.get_pdu_json() for pdu in auth_chain],
        }

    async def on_pdu_request(
        self, origin: str, event_id: str
    ) -> Tuple[int, Union[JsonDict, str]]:
        pdu = await self.handler.get_persisted_pdu(origin, event_id)

        if pdu:
            return 200, self._transaction_from_pdus([pdu]).get_dict()
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

        pdu = await self.handler.on_make_join_request(origin, room_id, user_id)
        time_now = self._clock.time_msec()
        return {"event": pdu.get_pdu_json(time_now), "room_version": room_version}

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
        pdu = await self._check_sigs_and_hash(room_version, pdu)
        ret_pdu = await self.handler.on_invite_request(origin, pdu, room_version)
        time_now = self._clock.time_msec()
        return {"event": ret_pdu.get_pdu_json(time_now)}

    async def on_send_join_request(
        self, origin: str, content: JsonDict, room_id: str
    ) -> Dict[str, Any]:
        logger.debug("on_send_join_request: content: %s", content)

        room_version = await self.store.get_room_version(room_id)
        pdu = event_from_pdu_json(content, room_version)

        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, pdu.room_id)

        logger.debug("on_send_join_request: pdu sigs: %s", pdu.signatures)

        pdu = await self._check_sigs_and_hash(room_version, pdu)

        res_pdus = await self.handler.on_send_join_request(origin, pdu)
        time_now = self._clock.time_msec()
        return {
            "state": [p.get_pdu_json(time_now) for p in res_pdus["state"]],
            "auth_chain": [p.get_pdu_json(time_now) for p in res_pdus["auth_chain"]],
        }

    async def on_make_leave_request(
        self, origin: str, room_id: str, user_id: str
    ) -> Dict[str, Any]:
        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, room_id)
        pdu = await self.handler.on_make_leave_request(origin, room_id, user_id)

        room_version = await self.store.get_room_version_id(room_id)

        time_now = self._clock.time_msec()
        return {"event": pdu.get_pdu_json(time_now), "room_version": room_version}

    async def on_send_leave_request(
        self, origin: str, content: JsonDict, room_id: str
    ) -> dict:
        logger.debug("on_send_leave_request: content: %s", content)

        room_version = await self.store.get_room_version(room_id)
        pdu = event_from_pdu_json(content, room_version)

        origin_host, _ = parse_server_name(origin)
        await self.check_server_matches_acl(origin_host, pdu.room_id)

        logger.debug("on_send_leave_request: pdu sigs: %s", pdu.signatures)

        pdu = await self._check_sigs_and_hash(room_version, pdu)

        await self.handler.on_send_leave_request(origin, pdu)
        return {}

    async def on_event_auth(
        self, origin: str, room_id: str, event_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        with (await self._server_linearizer.queue((origin, room_id))):
            origin_host, _ = parse_server_name(origin)
            await self.check_server_matches_acl(origin_host, room_id)

            time_now = self._clock.time_msec()
            auth_pdus = await self.handler.on_event_auth(event_id)
            res = {"auth_chain": [a.get_pdu_json(time_now) for a in auth_pdus]}
        return 200, res

    @log_function
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

        json_result = {}  # type: Dict[str, Dict[str, dict]]
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
        with (await self._server_linearizer.queue((origin, room_id))):
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

    @log_function
    async def on_openid_userinfo(self, token: str) -> Optional[str]:
        ts_now_ms = self._clock.time_msec()
        return await self.store.get_user_id_for_open_id_token(token, ts_now_ms)

    def _transaction_from_pdus(self, pdu_list: List[EventBase]) -> Transaction:
        """Returns a new Transaction containing the given PDUs suitable for
        transmission.
        """
        time_now = self._clock.time_msec()
        pdus = [p.get_pdu_json(time_now) for p in pdu_list]
        return Transaction(
            origin=self.server_name,
            pdus=pdus,
            origin_server_ts=int(time_now),
            destination=None,
        )

    async def _handle_received_pdu(self, origin: str, pdu: EventBase) -> None:
        """ Process a PDU received in a federation /send/ transaction.

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
        # check that it's actually being sent from a valid destination to
        # workaround bug #1753 in 0.18.5 and 0.18.6
        if origin != get_domain_from_id(pdu.sender):
            # We continue to accept join events from any server; this is
            # necessary for the federation join dance to work correctly.
            # (When we join over federation, the "helper" server is
            # responsible for sending out the join event, rather than the
            # origin. See bug #1893. This is also true for some third party
            # invites).
            if not (
                pdu.type == "m.room.member"
                and pdu.content
                and pdu.content.get("membership", None)
                in (Membership.JOIN, Membership.INVITE)
            ):
                logger.info(
                    "Discarding PDU %s from invalid origin %s", pdu.event_id, origin
                )
                return
            else:
                logger.info("Accepting join PDU %s from %s", pdu.event_id, origin)

        # We've already checked that we know the room version by this point
        room_version = await self.store.get_room_version(pdu.room_id)

        # Check signature.
        try:
            pdu = await self._check_sigs_and_hash(room_version, pdu)
        except SynapseError as e:
            raise FederationError("ERROR", e.code, e.msg, affected=pdu.event_id)

        await self.handler.on_receive_pdu(origin, pdu, sent_to_us_directly=True)

    def __str__(self):
        return "<ReplicationLayer(%s)>" % self.server_name

    async def exchange_third_party_invite(
        self, sender_user_id: str, target_user_id: str, room_id: str, signed: Dict
    ):
        ret = await self.handler.exchange_third_party_invite(
            sender_user_id, target_user_id, room_id, signed
        )
        return ret

    async def on_exchange_third_party_invite_request(
        self, room_id: str, event_dict: Dict
    ):
        ret = await self.handler.on_exchange_third_party_invite_request(
            room_id, event_dict
        )
        return ret

    async def check_server_matches_acl(self, server_name: str, room_id: str):
        """Check if the given server is allowed by the server ACLs in the room

        Args:
            server_name: name of server, *without any port part*
            room_id: ID of the room to check

        Raises:
            AuthError if the server does not match the ACL
        """
        state_ids = await self.store.get_current_state_ids(room_id)
        acl_event_id = state_ids.get((EventTypes.ServerACL, ""))

        if not acl_event_id:
            return

        acl_event = await self.store.get_event(acl_event_id)
        if server_matches_acl_event(server_name, acl_event):
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


def _acl_entry_matches(server_name: str, acl_entry: str) -> Match:
    if not isinstance(acl_entry, str):
        logger.warning(
            "Ignoring non-str ACL entry '%s' (is %s)", acl_entry, type(acl_entry)
        )
        return False
    regex = glob_to_regex(acl_entry)
    return regex.match(server_name)


class FederationHandlerRegistry:
    """Allows classes to register themselves as handlers for a given EDU or
    query type for incoming federation traffic.
    """

    def __init__(self, hs: "HomeServer"):
        self.config = hs.config
        self.http_client = hs.get_simple_http_client()
        self.clock = hs.get_clock()
        self._instance_name = hs.get_instance_name()

        # These are safe to load in monolith mode, but will explode if we try
        # and use them. However we have guards before we use them to ensure that
        # we don't route to ourselves, and in monolith mode that will always be
        # the case.
        self._get_query_client = ReplicationGetQueryRestServlet.make_client(hs)
        self._send_edu = ReplicationFederationSendEduRestServlet.make_client(hs)

        self.edu_handlers = (
            {}
        )  # type: Dict[str, Callable[[str, dict], Awaitable[None]]]
        self.query_handlers = {}  # type: Dict[str, Callable[[dict], Awaitable[None]]]

        # Map from type to instance name that we should route EDU handling to.
        self._edu_type_to_instance = {}  # type: Dict[str, str]

    def register_edu_handler(
        self, edu_type: str, handler: Callable[[str, dict], Awaitable[None]]
    ):
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
        self, query_type: str, handler: Callable[[dict], defer.Deferred]
    ):
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

    def register_instance_for_edu(self, edu_type: str, instance_name: str):
        """Register that the EDU handler is on a different instance than master.
        """
        self._edu_type_to_instance[edu_type] = instance_name

    async def on_edu(self, edu_type: str, origin: str, content: dict):
        if not self.config.use_presence and edu_type == "m.presence":
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
        route_to = self._edu_type_to_instance.get(edu_type, "master")
        if route_to != self._instance_name:
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

    async def on_query(self, query_type: str, args: dict):
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
