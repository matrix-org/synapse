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


from twisted.internet import defer

from .federation_base import FederationBase
from synapse.api.constants import Membership
from .units import Edu

from synapse.api.errors import (
    CodeMessageException, HttpResponseException, SynapseError,
)
from synapse.util import unwrapFirstError
from synapse.util.async import concurrently_execute
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.logutils import log_function
from synapse.events import FrozenEvent
import synapse.metrics

from synapse.util.retryutils import get_retry_limiter, NotRetryingDestination

import copy
import itertools
import logging
import random


logger = logging.getLogger(__name__)


# synapse.federation.federation_client is a silly name
metrics = synapse.metrics.get_metrics_for("synapse.federation.client")

sent_pdus_destination_dist = metrics.register_distribution("sent_pdu_destinations")

sent_edus_counter = metrics.register_counter("sent_edus")

sent_queries_counter = metrics.register_counter("sent_queries", labels=["type"])


class FederationClient(FederationBase):
    def __init__(self, hs):
        super(FederationClient, self).__init__(hs)

    def start_get_pdu_cache(self):
        self._get_pdu_cache = ExpiringCache(
            cache_name="get_pdu_cache",
            clock=self._clock,
            max_len=1000,
            expiry_ms=120 * 1000,
            reset_expiry_on_get=False,
        )

        self._get_pdu_cache.start()

    @log_function
    def send_pdu(self, pdu, destinations):
        """Informs the replication layer about a new PDU generated within the
        home server that should be transmitted to others.

        TODO: Figure out when we should actually resolve the deferred.

        Args:
            pdu (Pdu): The new Pdu.

        Returns:
            Deferred: Completes when we have successfully processed the PDU
            and replicated it to any interested remote home servers.
        """
        order = self._order
        self._order += 1

        sent_pdus_destination_dist.inc_by(len(destinations))

        logger.debug("[%s] transaction_layer.enqueue_pdu... ", pdu.event_id)

        # TODO, add errback, etc.
        self._transaction_queue.enqueue_pdu(pdu, destinations, order)

        logger.debug(
            "[%s] transaction_layer.enqueue_pdu... done",
            pdu.event_id
        )

    @log_function
    def send_edu(self, destination, edu_type, content):
        edu = Edu(
            origin=self.server_name,
            destination=destination,
            edu_type=edu_type,
            content=content,
        )

        sent_edus_counter.inc()

        # TODO, add errback, etc.
        self._transaction_queue.enqueue_edu(edu)
        return defer.succeed(None)

    @log_function
    def send_failure(self, failure, destination):
        self._transaction_queue.enqueue_failure(failure, destination)
        return defer.succeed(None)

    @log_function
    def make_query(self, destination, query_type, args,
                   retry_on_dns_fail=False):
        """Sends a federation Query to a remote homeserver of the given type
        and arguments.

        Args:
            destination (str): Domain name of the remote homeserver
            query_type (str): Category of the query type; should match the
                handler name used in register_query_handler().
            args (dict): Mapping of strings to strings containing the details
                of the query request.

        Returns:
            a Deferred which will eventually yield a JSON object from the
            response
        """
        sent_queries_counter.inc(query_type)

        return self.transport_layer.make_query(
            destination, query_type, args, retry_on_dns_fail=retry_on_dns_fail
        )

    @log_function
    def query_client_keys(self, destination, content):
        """Query device keys for a device hosted on a remote server.

        Args:
            destination (str): Domain name of the remote homeserver
            content (dict): The query content.

        Returns:
            a Deferred which will eventually yield a JSON object from the
            response
        """
        sent_queries_counter.inc("client_device_keys")
        return self.transport_layer.query_client_keys(destination, content)

    @log_function
    def claim_client_keys(self, destination, content):
        """Claims one-time keys for a device hosted on a remote server.

        Args:
            destination (str): Domain name of the remote homeserver
            content (dict): The query content.

        Returns:
            a Deferred which will eventually yield a JSON object from the
            response
        """
        sent_queries_counter.inc("client_one_time_keys")
        return self.transport_layer.claim_client_keys(destination, content)

    @defer.inlineCallbacks
    @log_function
    def backfill(self, dest, context, limit, extremities):
        """Requests some more historic PDUs for the given context from the
        given destination server.

        Args:
            dest (str): The remote home server to ask.
            context (str): The context to backfill.
            limit (int): The maximum number of PDUs to return.
            extremities (list): List of PDU id and origins of the first pdus
                we have seen from the context

        Returns:
            Deferred: Results in the received PDUs.
        """
        logger.debug("backfill extrem=%s", extremities)

        # If there are no extremeties then we've (probably) reached the start.
        if not extremities:
            return

        transaction_data = yield self.transport_layer.backfill(
            dest, context, extremities, limit)

        logger.debug("backfill transaction_data=%s", repr(transaction_data))

        pdus = [
            self.event_from_pdu_json(p, outlier=False)
            for p in transaction_data["pdus"]
        ]

        # FIXME: We should handle signature failures more gracefully.
        pdus[:] = yield defer.gatherResults(
            self._check_sigs_and_hashes(pdus),
            consumeErrors=True,
        ).addErrback(unwrapFirstError)

        defer.returnValue(pdus)

    @defer.inlineCallbacks
    @log_function
    def get_pdu(self, destinations, event_id, outlier=False, timeout=None):
        """Requests the PDU with given origin and ID from the remote home
        servers.

        Will attempt to get the PDU from each destination in the list until
        one succeeds.

        This will persist the PDU locally upon receipt.

        Args:
            destinations (list): Which home servers to query
            pdu_origin (str): The home server that originally sent the pdu.
            event_id (str)
            outlier (bool): Indicates whether the PDU is an `outlier`, i.e. if
                it's from an arbitary point in the context as opposed to part
                of the current block of PDUs. Defaults to `False`
            timeout (int): How long to try (in ms) each destination for before
                moving to the next destination. None indicates no timeout.

        Returns:
            Deferred: Results in the requested PDU.
        """

        # TODO: Rate limit the number of times we try and get the same event.

        if self._get_pdu_cache:
            ev = self._get_pdu_cache.get(event_id)
            if ev:
                defer.returnValue(ev)

        pdu = None
        for destination in destinations:
            try:
                limiter = yield get_retry_limiter(
                    destination,
                    self._clock,
                    self.store,
                )

                with limiter:
                    transaction_data = yield self.transport_layer.get_event(
                        destination, event_id, timeout=timeout,
                    )

                    logger.debug("transaction_data %r", transaction_data)

                    pdu_list = [
                        self.event_from_pdu_json(p, outlier=outlier)
                        for p in transaction_data["pdus"]
                    ]

                    if pdu_list and pdu_list[0]:
                        pdu = pdu_list[0]

                        # Check signatures are correct.
                        pdu = yield self._check_sigs_and_hashes([pdu])[0]

                        break

            except SynapseError as e:
                logger.info(
                    "Failed to get PDU %s from %s because %s",
                    event_id, destination, e,
                )
                continue
            except CodeMessageException as e:
                if 400 <= e.code < 500:
                    raise

                logger.info(
                    "Failed to get PDU %s from %s because %s",
                    event_id, destination, e,
                )
                continue
            except NotRetryingDestination as e:
                logger.info(e.message)
                continue
            except Exception as e:
                logger.info(
                    "Failed to get PDU %s from %s because %s",
                    event_id, destination, e,
                )
                continue

        if self._get_pdu_cache is not None and pdu:
            self._get_pdu_cache[event_id] = pdu

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    @log_function
    def get_state_for_room(self, destination, room_id, event_id):
        """Requests all of the `current` state PDUs for a given room from
        a remote home server.

        Args:
            destination (str): The remote homeserver to query for the state.
            room_id (str): The id of the room we're interested in.
            event_id (str): The id of the event we want the state at.

        Returns:
            Deferred: Results in a list of PDUs.
        """

        try:
            # First we try and ask for just the IDs, as thats far quicker if
            # we have most of the state and auth_chain already.
            # However, this may 404 if the other side has an old synapse.
            result = yield self.transport_layer.get_room_state_ids(
                destination, room_id, event_id=event_id,
            )

            state_event_ids = result["pdu_ids"]
            auth_event_ids = result.get("auth_chain_ids", [])

            fetched_events, failed_to_fetch = yield self.get_events(
                [destination], room_id, set(state_event_ids + auth_event_ids)
            )

            if failed_to_fetch:
                logger.warn("Failed to get %r", failed_to_fetch)

            event_map = {
                ev.event_id: ev for ev in fetched_events
            }

            pdus = [event_map[e_id] for e_id in state_event_ids if e_id in event_map]
            auth_chain = [
                event_map[e_id] for e_id in auth_event_ids if e_id in event_map
            ]

            auth_chain.sort(key=lambda e: e.depth)

            defer.returnValue((pdus, auth_chain))
        except HttpResponseException as e:
            if e.code == 400 or e.code == 404:
                logger.info("Failed to use get_room_state_ids API, falling back")
            else:
                raise e

        result = yield self.transport_layer.get_room_state(
            destination, room_id, event_id=event_id,
        )

        pdus = [
            self.event_from_pdu_json(p, outlier=True) for p in result["pdus"]
        ]

        auth_chain = [
            self.event_from_pdu_json(p, outlier=True)
            for p in result.get("auth_chain", [])
        ]

        seen_events = yield self.store.get_events([
            ev.event_id for ev in itertools.chain(pdus, auth_chain)
        ])

        signed_pdus = yield self._check_sigs_and_hash_and_fetch(
            destination,
            [p for p in pdus if p.event_id not in seen_events],
            outlier=True
        )
        signed_pdus.extend(
            seen_events[p.event_id] for p in pdus if p.event_id in seen_events
        )

        signed_auth = yield self._check_sigs_and_hash_and_fetch(
            destination,
            [p for p in auth_chain if p.event_id not in seen_events],
            outlier=True
        )
        signed_auth.extend(
            seen_events[p.event_id] for p in auth_chain if p.event_id in seen_events
        )

        signed_auth.sort(key=lambda e: e.depth)

        defer.returnValue((signed_pdus, signed_auth))

    @defer.inlineCallbacks
    def get_events(self, destinations, room_id, event_ids, return_local=True):
        """Fetch events from some remote destinations, checking if we already
        have them.

        Args:
            destinations (list)
            room_id (str)
            event_ids (list)
            return_local (bool): Whether to include events we already have in
                the DB in the returned list of events

        Returns:
            Deferred: A deferred resolving to a 2-tuple where the first is a list of
            events and the second is a list of event ids that we failed to fetch.
        """
        if return_local:
            seen_events = yield self.store.get_events(event_ids)
            signed_events = seen_events.values()
        else:
            seen_events = yield self.store.have_events(event_ids)
            signed_events = []

        failed_to_fetch = set()

        missing_events = set(event_ids)
        for k in seen_events:
            missing_events.discard(k)

        if not missing_events:
            defer.returnValue((signed_events, failed_to_fetch))

        def random_server_list():
            srvs = list(destinations)
            random.shuffle(srvs)
            return srvs

        batch_size = 20
        missing_events = list(missing_events)
        for i in xrange(0, len(missing_events), batch_size):
            batch = set(missing_events[i:i + batch_size])

            deferreds = [
                self.get_pdu(
                    destinations=random_server_list(),
                    event_id=e_id,
                )
                for e_id in batch
            ]

            res = yield defer.DeferredList(deferreds, consumeErrors=True)
            for success, result in res:
                if success:
                    signed_events.append(result)
                    batch.discard(result.event_id)

            # We removed all events we successfully fetched from `batch`
            failed_to_fetch.update(batch)

        defer.returnValue((signed_events, failed_to_fetch))

    @defer.inlineCallbacks
    @log_function
    def get_event_auth(self, destination, room_id, event_id):
        res = yield self.transport_layer.get_event_auth(
            destination, room_id, event_id,
        )

        auth_chain = [
            self.event_from_pdu_json(p, outlier=True)
            for p in res["auth_chain"]
        ]

        signed_auth = yield self._check_sigs_and_hash_and_fetch(
            destination, auth_chain, outlier=True
        )

        signed_auth.sort(key=lambda e: e.depth)

        defer.returnValue(signed_auth)

    @defer.inlineCallbacks
    def make_membership_event(self, destinations, room_id, user_id, membership,
                              content={},):
        """
        Creates an m.room.member event, with context, without participating in the room.

        Does so by asking one of the already participating servers to create an
        event with proper context.

        Note that this does not append any events to any graphs.

        Args:
            destinations (str): Candidate homeservers which are probably
                participating in the room.
            room_id (str): The room in which the event will happen.
            user_id (str): The user whose membership is being evented.
            membership (str): The "membership" property of the event. Must be
                one of "join" or "leave".
            content (object): Any additional data to put into the content field
                of the event.
        Return:
            A tuple of (origin (str), event (object)) where origin is the remote
            homeserver which generated the event.
        """
        valid_memberships = {Membership.JOIN, Membership.LEAVE}
        if membership not in valid_memberships:
            raise RuntimeError(
                "make_membership_event called with membership='%s', must be one of %s" %
                (membership, ",".join(valid_memberships))
            )
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                ret = yield self.transport_layer.make_membership_event(
                    destination, room_id, user_id, membership
                )

                pdu_dict = ret["event"]

                logger.debug("Got response to make_%s: %s", membership, pdu_dict)

                pdu_dict["content"].update(content)

                # The protoevent received over the JSON wire may not have all
                # the required fields. Lets just gloss over that because
                # there's some we never care about
                if "prev_state" not in pdu_dict:
                    pdu_dict["prev_state"] = []

                defer.returnValue(
                    (destination, self.event_from_pdu_json(pdu_dict))
                )
                break
            except CodeMessageException as e:
                if not 500 <= e.code < 600:
                    raise
                else:
                    logger.warn(
                        "Failed to make_%s via %s: %s",
                        membership, destination, e.message
                    )
            except Exception as e:
                logger.warn(
                    "Failed to make_%s via %s: %s",
                    membership, destination, e.message
                )

        raise RuntimeError("Failed to send to any server.")

    @defer.inlineCallbacks
    def send_join(self, destinations, pdu):
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                time_now = self._clock.time_msec()
                _, content = yield self.transport_layer.send_join(
                    destination=destination,
                    room_id=pdu.room_id,
                    event_id=pdu.event_id,
                    content=pdu.get_pdu_json(time_now),
                )

                logger.debug("Got content: %s", content)

                state = [
                    self.event_from_pdu_json(p, outlier=True)
                    for p in content.get("state", [])
                ]

                auth_chain = [
                    self.event_from_pdu_json(p, outlier=True)
                    for p in content.get("auth_chain", [])
                ]

                pdus = {
                    p.event_id: p
                    for p in itertools.chain(state, auth_chain)
                }

                valid_pdus = yield self._check_sigs_and_hash_and_fetch(
                    destination, pdus.values(),
                    outlier=True,
                )

                valid_pdus_map = {
                    p.event_id: p
                    for p in valid_pdus
                }

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

                auth_chain.sort(key=lambda e: e.depth)

                defer.returnValue({
                    "state": signed_state,
                    "auth_chain": signed_auth,
                    "origin": destination,
                })
            except CodeMessageException as e:
                if not 500 <= e.code < 600:
                    raise
                else:
                    logger.exception(
                        "Failed to send_join via %s: %s",
                        destination, e.message
                    )
            except Exception as e:
                logger.exception(
                    "Failed to send_join via %s: %s",
                    destination, e.message
                )

        raise RuntimeError("Failed to send to any server.")

    @defer.inlineCallbacks
    def send_invite(self, destination, room_id, event_id, pdu):
        time_now = self._clock.time_msec()
        code, content = yield self.transport_layer.send_invite(
            destination=destination,
            room_id=room_id,
            event_id=event_id,
            content=pdu.get_pdu_json(time_now),
        )

        pdu_dict = content["event"]

        logger.debug("Got response to send_invite: %s", pdu_dict)

        pdu = self.event_from_pdu_json(pdu_dict)

        # Check signatures are correct.
        pdu = yield self._check_sigs_and_hash(pdu)

        # FIXME: We should handle signature failures more gracefully.

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    def send_leave(self, destinations, pdu):
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                time_now = self._clock.time_msec()
                _, content = yield self.transport_layer.send_leave(
                    destination=destination,
                    room_id=pdu.room_id,
                    event_id=pdu.event_id,
                    content=pdu.get_pdu_json(time_now),
                )

                logger.debug("Got content: %s", content)
                defer.returnValue(None)
            except CodeMessageException:
                raise
            except Exception as e:
                logger.exception(
                    "Failed to send_leave via %s: %s",
                    destination, e.message
                )

        raise RuntimeError("Failed to send to any server.")

    @defer.inlineCallbacks
    def get_public_rooms(self, destinations):
        results_by_server = {}

        @defer.inlineCallbacks
        def _get_result(s):
            if s == self.server_name:
                defer.returnValue()

            try:
                result = yield self.transport_layer.get_public_rooms(s)
                results_by_server[s] = result
            except:
                logger.exception("Error getting room list from server %r", s)

        yield concurrently_execute(_get_result, destinations, 3)

        defer.returnValue(results_by_server)

    @defer.inlineCallbacks
    def query_auth(self, destination, room_id, event_id, local_auth):
        """
        Params:
            destination (str)
            event_it (str)
            local_auth (list)
        """
        time_now = self._clock.time_msec()

        send_content = {
            "auth_chain": [e.get_pdu_json(time_now) for e in local_auth],
        }

        code, content = yield self.transport_layer.send_query_auth(
            destination=destination,
            room_id=room_id,
            event_id=event_id,
            content=send_content,
        )

        auth_chain = [
            self.event_from_pdu_json(e)
            for e in content["auth_chain"]
        ]

        signed_auth = yield self._check_sigs_and_hash_and_fetch(
            destination, auth_chain, outlier=True
        )

        signed_auth.sort(key=lambda e: e.depth)

        ret = {
            "auth_chain": signed_auth,
            "rejects": content.get("rejects", []),
            "missing": content.get("missing", []),
        }

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_missing_events(self, destination, room_id, earliest_events_ids,
                           latest_events, limit, min_depth):
        """Tries to fetch events we are missing. This is called when we receive
        an event without having received all of its ancestors.

        Args:
            destination (str)
            room_id (str)
            earliest_events_ids (list): List of event ids. Effectively the
                events we expected to receive, but haven't. `get_missing_events`
                should only return events that didn't happen before these.
            latest_events (list): List of events we have received that we don't
                have all previous events for.
            limit (int): Maximum number of events to return.
            min_depth (int): Minimum depth of events tor return.
        """
        try:
            content = yield self.transport_layer.get_missing_events(
                destination=destination,
                room_id=room_id,
                earliest_events=earliest_events_ids,
                latest_events=[e.event_id for e in latest_events],
                limit=limit,
                min_depth=min_depth,
            )

            events = [
                self.event_from_pdu_json(e)
                for e in content.get("events", [])
            ]

            signed_events = yield self._check_sigs_and_hash_and_fetch(
                destination, events, outlier=False
            )

            have_gotten_all_from_destination = True
        except HttpResponseException as e:
            if not e.code == 400:
                raise

            # We are probably hitting an old server that doesn't support
            # get_missing_events
            signed_events = []
            have_gotten_all_from_destination = False

        if len(signed_events) >= limit:
            defer.returnValue(signed_events)

        servers = yield self.store.get_joined_hosts_for_room(room_id)

        servers = set(servers)
        servers.discard(self.server_name)

        failed_to_fetch = set()

        while len(signed_events) < limit:
            # Are we missing any?

            seen_events = set(earliest_events_ids)
            seen_events.update(e.event_id for e in signed_events if e)

            missing_events = {}
            for e in itertools.chain(latest_events, signed_events):
                if e.depth > min_depth:
                    missing_events.update({
                        e_id: e.depth for e_id, _ in e.prev_events
                        if e_id not in seen_events
                        and e_id not in failed_to_fetch
                    })

            if not missing_events:
                break

            have_seen = yield self.store.have_events(missing_events)

            for k in have_seen:
                missing_events.pop(k, None)

            if not missing_events:
                break

            # Okay, we haven't gotten everything yet. Lets get them.
            ordered_missing = sorted(missing_events.items(), key=lambda x: x[0])

            if have_gotten_all_from_destination:
                servers.discard(destination)

            def random_server_list():
                srvs = list(servers)
                random.shuffle(srvs)
                return srvs

            deferreds = [
                self.get_pdu(
                    destinations=random_server_list(),
                    event_id=e_id,
                )
                for e_id, depth in ordered_missing[:limit - len(signed_events)]
            ]

            res = yield defer.DeferredList(deferreds, consumeErrors=True)
            for (result, val), (e_id, _) in zip(res, ordered_missing):
                if result and val:
                    signed_events.append(val)
                else:
                    failed_to_fetch.add(e_id)

        defer.returnValue(signed_events)

    def event_from_pdu_json(self, pdu_json, outlier=False):
        event = FrozenEvent(
            pdu_json
        )

        event.internal_metadata.outlier = outlier

        return event

    @defer.inlineCallbacks
    def forward_third_party_invite(self, destinations, room_id, event_dict):
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                yield self.transport_layer.exchange_third_party_invite(
                    destination=destination,
                    room_id=room_id,
                    event_dict=event_dict,
                )
                defer.returnValue(None)
            except CodeMessageException:
                raise
            except Exception as e:
                logger.exception(
                    "Failed to send_third_party_invite via %s: %s",
                    destination, e.message
                )

        raise RuntimeError("Failed to send to any server.")
