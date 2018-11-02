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
import random

from six.moves import range

from prometheus_client import Counter

from twisted.internet import defer

from synapse.api.constants import KNOWN_ROOM_VERSIONS, EventTypes, Membership
from synapse.api.errors import (
    CodeMessageException,
    FederationDeniedError,
    HttpResponseException,
    SynapseError,
)
from synapse.events import builder
from synapse.federation.federation_base import FederationBase, event_from_pdu_json
from synapse.util import logcontext, unwrapFirstError
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.logcontext import make_deferred_yieldable, run_in_background
from synapse.util.logutils import log_function
from synapse.util.retryutils import NotRetryingDestination

logger = logging.getLogger(__name__)

sent_queries_counter = Counter("synapse_federation_client_sent_queries", "", ["type"])


PDU_RETRY_TIME_MS = 1 * 60 * 1000


class InvalidResponseError(RuntimeError):
    """Helper for _try_destination_list: indicates that the server returned a response
    we couldn't parse
    """
    pass


class FederationClient(FederationBase):
    def __init__(self, hs):
        super(FederationClient, self).__init__(hs)

        self.pdu_destination_tried = {}
        self._clock.looping_call(
            self._clear_tried_cache, 60 * 1000,
        )
        self.state = hs.get_state_handler()
        self.transport_layer = hs.get_federation_transport_client()

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
    def make_query(self, destination, query_type, args,
                   retry_on_dns_fail=False, ignore_backoff=False):
        """Sends a federation Query to a remote homeserver of the given type
        and arguments.

        Args:
            destination (str): Domain name of the remote homeserver
            query_type (str): Category of the query type; should match the
                handler name used in register_query_handler().
            args (dict): Mapping of strings to strings containing the details
                of the query request.
            ignore_backoff (bool): true to ignore the historical backoff data
                and try the request anyway.

        Returns:
            a Deferred which will eventually yield a JSON object from the
            response
        """
        sent_queries_counter.labels(query_type).inc()

        return self.transport_layer.make_query(
            destination, query_type, args, retry_on_dns_fail=retry_on_dns_fail,
            ignore_backoff=ignore_backoff,
        )

    @log_function
    def query_client_keys(self, destination, content, timeout):
        """Query device keys for a device hosted on a remote server.

        Args:
            destination (str): Domain name of the remote homeserver
            content (dict): The query content.

        Returns:
            a Deferred which will eventually yield a JSON object from the
            response
        """
        sent_queries_counter.labels("client_device_keys").inc()
        return self.transport_layer.query_client_keys(
            destination, content, timeout
        )

    @log_function
    def query_user_devices(self, destination, user_id, timeout=30000):
        """Query the device keys for a list of user ids hosted on a remote
        server.
        """
        sent_queries_counter.labels("user_devices").inc()
        return self.transport_layer.query_user_devices(
            destination, user_id, timeout
        )

    @log_function
    def claim_client_keys(self, destination, content, timeout):
        """Claims one-time keys for a device hosted on a remote server.

        Args:
            destination (str): Domain name of the remote homeserver
            content (dict): The query content.

        Returns:
            a Deferred which will eventually yield a JSON object from the
            response
        """
        sent_queries_counter.labels("client_one_time_keys").inc()
        return self.transport_layer.claim_client_keys(
            destination, content, timeout
        )

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
            event_from_pdu_json(p, outlier=False)
            for p in transaction_data["pdus"]
        ]

        # FIXME: We should handle signature failures more gracefully.
        pdus[:] = yield logcontext.make_deferred_yieldable(defer.gatherResults(
            self._check_sigs_and_hashes(pdus),
            consumeErrors=True,
        ).addErrback(unwrapFirstError))

        defer.returnValue(pdus)

    @defer.inlineCallbacks
    @log_function
    def get_pdu(self, destinations, event_id, outlier=False, timeout=None):
        """Requests the PDU with given origin and ID from the remote home
        servers.

        Will attempt to get the PDU from each destination in the list until
        one succeeds.

        Args:
            destinations (list): Which home servers to query
            event_id (str): event to fetch
            outlier (bool): Indicates whether the PDU is an `outlier`, i.e. if
                it's from an arbitary point in the context as opposed to part
                of the current block of PDUs. Defaults to `False`
            timeout (int): How long to try (in ms) each destination for before
                moving to the next destination. None indicates no timeout.

        Returns:
            Deferred: Results in the requested PDU.
        """

        # TODO: Rate limit the number of times we try and get the same event.

        ev = self._get_pdu_cache.get(event_id)
        if ev:
            defer.returnValue(ev)

        pdu_attempts = self.pdu_destination_tried.setdefault(event_id, {})

        signed_pdu = None
        for destination in destinations:
            now = self._clock.time_msec()
            last_attempt = pdu_attempts.get(destination, 0)
            if last_attempt + PDU_RETRY_TIME_MS > now:
                continue

            try:
                transaction_data = yield self.transport_layer.get_event(
                    destination, event_id, timeout=timeout,
                )

                logger.debug("transaction_data %r", transaction_data)

                pdu_list = [
                    event_from_pdu_json(p, outlier=outlier)
                    for p in transaction_data["pdus"]
                ]

                if pdu_list and pdu_list[0]:
                    pdu = pdu_list[0]

                    # Check signatures are correct.
                    signed_pdu = yield self._check_sigs_and_hash(pdu)

                    break

                pdu_attempts[destination] = now

            except SynapseError as e:
                logger.info(
                    "Failed to get PDU %s from %s because %s",
                    event_id, destination, e,
                )
            except NotRetryingDestination as e:
                logger.info(str(e))
                continue
            except FederationDeniedError as e:
                logger.info(str(e))
                continue
            except Exception as e:
                pdu_attempts[destination] = now

                logger.info(
                    "Failed to get PDU %s from %s because %s",
                    event_id, destination, e,
                )
                continue

        if signed_pdu:
            self._get_pdu_cache[event_id] = signed_pdu

        defer.returnValue(signed_pdu)

    @defer.inlineCallbacks
    @log_function
    def get_state_for_room(self, destination, room_id, event_id):
        """Requests all of the room state at a given event from a remote home server.

        Args:
            destination (str): The remote homeserver to query for the state.
            room_id (str): The id of the room we're interested in.
            event_id (str): The id of the event we want the state at.

        Returns:
            Deferred[Tuple[List[EventBase], List[EventBase]]]:
                A list of events in the state, and a list of events in the auth chain
                for the given event.
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
            event_from_pdu_json(p, outlier=True) for p in result["pdus"]
        ]

        auth_chain = [
            event_from_pdu_json(p, outlier=True)
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
            seen_events = yield self.store.get_events(event_ids, allow_rejected=True)
            signed_events = list(seen_events.values())
        else:
            seen_events = yield self.store.have_seen_events(event_ids)
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
        for i in range(0, len(missing_events), batch_size):
            batch = set(missing_events[i:i + batch_size])

            deferreds = [
                run_in_background(
                    self.get_pdu,
                    destinations=random_server_list(),
                    event_id=e_id,
                )
                for e_id in batch
            ]

            res = yield make_deferred_yieldable(
                defer.DeferredList(deferreds, consumeErrors=True)
            )
            for success, result in res:
                if success and result:
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
            event_from_pdu_json(p, outlier=True)
            for p in res["auth_chain"]
        ]

        signed_auth = yield self._check_sigs_and_hash_and_fetch(
            destination, auth_chain, outlier=True
        )

        signed_auth.sort(key=lambda e: e.depth)

        defer.returnValue(signed_auth)

    @defer.inlineCallbacks
    def _try_destination_list(self, description, destinations, callback):
        """Try an operation on a series of servers, until it succeeds

        Args:
            description (unicode): description of the operation we're doing, for logging

            destinations (Iterable[unicode]): list of server_names to try

            callback (callable):  Function to run for each server. Passed a single
                argument: the server_name to try. May return a deferred.

                If the callback raises a CodeMessageException with a 300/400 code,
                attempts to perform the operation stop immediately and the exception is
                reraised.

                Otherwise, if the callback raises an Exception the error is logged and the
                next server tried. Normally the stacktrace is logged but this is
                suppressed if the exception is an InvalidResponseError.

        Returns:
            The [Deferred] result of callback, if it succeeds

        Raises:
            SynapseError if the chosen remote server returns a 300/400 code.

            RuntimeError if no servers were reachable.
        """
        for destination in destinations:
            if destination == self.server_name:
                continue

            try:
                res = yield callback(destination)
                defer.returnValue(res)
            except InvalidResponseError as e:
                logger.warn(
                    "Failed to %s via %s: %s",
                    description, destination, e,
                )
            except HttpResponseException as e:
                if not 500 <= e.code < 600:
                    raise e.to_synapse_error()
                else:
                    logger.warn(
                        "Failed to %s via %s: %i %s",
                        description, destination, e.code, e.args[0],
                    )
            except Exception:
                logger.warn(
                    "Failed to %s via %s",
                    description, destination, exc_info=1,
                )

        raise RuntimeError("Failed to %s via any server" % (description, ))

    def make_membership_event(self, destinations, room_id, user_id, membership,
                              content, params):
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
            content (dict): Any additional data to put into the content field
                of the event.
            params (dict[str, str|Iterable[str]]): Query parameters to include in the
                request.
        Return:
            Deferred: resolves to a tuple of (origin (str), event (object))
            where origin is the remote homeserver which generated the event.

            Fails with a ``SynapseError`` if the chosen remote server
            returns a 300/400 code.

            Fails with a ``RuntimeError`` if no servers were reachable.
        """
        valid_memberships = {Membership.JOIN, Membership.LEAVE}
        if membership not in valid_memberships:
            raise RuntimeError(
                "make_membership_event called with membership='%s', must be one of %s" %
                (membership, ",".join(valid_memberships))
            )

        @defer.inlineCallbacks
        def send_request(destination):
            ret = yield self.transport_layer.make_membership_event(
                destination, room_id, user_id, membership, params,
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

            ev = builder.EventBuilder(pdu_dict)

            defer.returnValue(
                (destination, ev)
            )

        return self._try_destination_list(
            "make_" + membership, destinations, send_request,
        )

    def send_join(self, destinations, pdu):
        """Sends a join event to one of a list of homeservers.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        Args:
            destinations (str): Candidate homeservers which are probably
                participating in the room.
            pdu (BaseEvent): event to be sent

        Return:
            Deferred: resolves to a dict with members ``origin`` (a string
            giving the serer the event was sent to, ``state`` (?) and
            ``auth_chain``.

            Fails with a ``SynapseError`` if the chosen remote server
            returns a 300/400 code.

            Fails with a ``RuntimeError`` if no servers were reachable.
        """

        def check_authchain_validity(signed_auth_chain):
            for e in signed_auth_chain:
                if e.type == EventTypes.Create:
                    create_event = e
                    break
            else:
                raise InvalidResponseError(
                    "no %s in auth chain" % (EventTypes.Create,),
                )

            # the room version should be sane.
            room_version = create_event.content.get("room_version", "1")
            if room_version not in KNOWN_ROOM_VERSIONS:
                # This shouldn't be possible, because the remote server should have
                # rejected the join attempt during make_join.
                raise InvalidResponseError(
                    "room appears to have unsupported version %s" % (
                        room_version,
                    ))

        @defer.inlineCallbacks
        def send_request(destination):
            time_now = self._clock.time_msec()
            _, content = yield self.transport_layer.send_join(
                destination=destination,
                room_id=pdu.room_id,
                event_id=pdu.event_id,
                content=pdu.get_pdu_json(time_now),
            )

            logger.debug("Got content: %s", content)

            state = [
                event_from_pdu_json(p, outlier=True)
                for p in content.get("state", [])
            ]

            auth_chain = [
                event_from_pdu_json(p, outlier=True)
                for p in content.get("auth_chain", [])
            ]

            pdus = {
                p.event_id: p
                for p in itertools.chain(state, auth_chain)
            }

            valid_pdus = yield self._check_sigs_and_hash_and_fetch(
                destination, list(pdus.values()),
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

            check_authchain_validity(signed_auth)

            defer.returnValue({
                "state": signed_state,
                "auth_chain": signed_auth,
                "origin": destination,
            })
        return self._try_destination_list("send_join", destinations, send_request)

    @defer.inlineCallbacks
    def send_invite(self, destination, room_id, event_id, pdu):
        time_now = self._clock.time_msec()
        try:
            code, content = yield self.transport_layer.send_invite(
                destination=destination,
                room_id=room_id,
                event_id=event_id,
                content=pdu.get_pdu_json(time_now),
            )
        except HttpResponseException as e:
            if e.code == 403:
                raise e.to_synapse_error()
            raise

        pdu_dict = content["event"]

        logger.debug("Got response to send_invite: %s", pdu_dict)

        pdu = event_from_pdu_json(pdu_dict)

        # Check signatures are correct.
        pdu = yield self._check_sigs_and_hash(pdu)

        # FIXME: We should handle signature failures more gracefully.

        defer.returnValue(pdu)

    def send_leave(self, destinations, pdu):
        """Sends a leave event to one of a list of homeservers.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        This is mostly useful to reject received invites.

        Args:
            destinations (str): Candidate homeservers which are probably
                participating in the room.
            pdu (BaseEvent): event to be sent

        Return:
            Deferred: resolves to None.

            Fails with a ``SynapseError`` if the chosen remote server
            returns a 300/400 code.

            Fails with a ``RuntimeError`` if no servers were reachable.
        """
        @defer.inlineCallbacks
        def send_request(destination):
            time_now = self._clock.time_msec()
            _, content = yield self.transport_layer.send_leave(
                destination=destination,
                room_id=pdu.room_id,
                event_id=pdu.event_id,
                content=pdu.get_pdu_json(time_now),
            )

            logger.debug("Got content: %s", content)
            defer.returnValue(None)

        return self._try_destination_list("send_leave", destinations, send_request)

    def get_public_rooms(self, destination, limit=None, since_token=None,
                         search_filter=None, include_all_networks=False,
                         third_party_instance_id=None):
        if destination == self.server_name:
            return

        return self.transport_layer.get_public_rooms(
            destination, limit, since_token, search_filter,
            include_all_networks=include_all_networks,
            third_party_instance_id=third_party_instance_id,
        )

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
            event_from_pdu_json(e)
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
                           latest_events, limit, min_depth, timeout):
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
            timeout (int): Max time to wait in ms
        """
        try:
            content = yield self.transport_layer.get_missing_events(
                destination=destination,
                room_id=room_id,
                earliest_events=earliest_events_ids,
                latest_events=[e.event_id for e in latest_events],
                limit=limit,
                min_depth=min_depth,
                timeout=timeout,
            )

            events = [
                event_from_pdu_json(e)
                for e in content.get("events", [])
            ]

            signed_events = yield self._check_sigs_and_hash_and_fetch(
                destination, events, outlier=False
            )
        except HttpResponseException as e:
            if not e.code == 400:
                raise

            # We are probably hitting an old server that doesn't support
            # get_missing_events
            signed_events = []

        defer.returnValue(signed_events)

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
                    destination, str(e)
                )

        raise RuntimeError("Failed to send to any server.")
