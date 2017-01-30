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
from .units import Transaction, Edu

from synapse.util.async import Linearizer
from synapse.util.logutils import log_function
from synapse.util.caches.response_cache import ResponseCache
from synapse.events import FrozenEvent
from synapse.types import get_domain_from_id
import synapse.metrics

from synapse.api.errors import AuthError, FederationError, SynapseError

from synapse.crypto.event_signing import compute_event_signature

import simplejson as json
import logging


logger = logging.getLogger(__name__)

# synapse.federation.federation_server is a silly name
metrics = synapse.metrics.get_metrics_for("synapse.federation.server")

received_pdus_counter = metrics.register_counter("received_pdus")

received_edus_counter = metrics.register_counter("received_edus")

received_queries_counter = metrics.register_counter("received_queries", labels=["type"])


class FederationServer(FederationBase):
    def __init__(self, hs):
        super(FederationServer, self).__init__(hs)

        self.auth = hs.get_auth()

        self._room_pdu_linearizer = Linearizer("fed_room_pdu")
        self._server_linearizer = Linearizer("fed_server")

        # We cache responses to state queries, as they take a while and often
        # come in waves.
        self._state_resp_cache = ResponseCache(hs, timeout_ms=30000)

    def set_handler(self, handler):
        """Sets the handler that the replication layer will use to communicate
        receipt of new PDUs from other home servers. The required methods are
        documented on :py:class:`.ReplicationHandler`.
        """
        self.handler = handler

    def register_edu_handler(self, edu_type, handler):
        if edu_type in self.edu_handlers:
            raise KeyError("Already have an EDU handler for %s" % (edu_type,))

        self.edu_handlers[edu_type] = handler

    def register_query_handler(self, query_type, handler):
        """Sets the handler callable that will be used to handle an incoming
        federation Query of the given type.

        Args:
            query_type (str): Category name of the query, which should match
                the string used by make_query.
            handler (callable): Invoked to handle incoming queries of this type

        handler is invoked as:
            result = handler(args)

        where 'args' is a dict mapping strings to strings of the query
          arguments. It should return a Deferred that will eventually yield an
          object to encode as JSON.
        """
        if query_type in self.query_handlers:
            raise KeyError(
                "Already have a Query handler for %s" % (query_type,)
            )

        self.query_handlers[query_type] = handler

    @defer.inlineCallbacks
    @log_function
    def on_backfill_request(self, origin, room_id, versions, limit):
        with (yield self._server_linearizer.queue((origin, room_id))):
            pdus = yield self.handler.on_backfill_request(
                origin, room_id, versions, limit
            )

            res = self._transaction_from_pdus(pdus).get_dict()

        defer.returnValue((200, res))

    @defer.inlineCallbacks
    @log_function
    def on_incoming_transaction(self, transaction_data):
        transaction = Transaction(**transaction_data)

        received_pdus_counter.inc_by(len(transaction.pdus))

        for p in transaction.pdus:
            if "unsigned" in p:
                unsigned = p["unsigned"]
                if "age" in unsigned:
                    p["age"] = unsigned["age"]
            if "age" in p:
                p["age_ts"] = int(self._clock.time_msec()) - int(p["age"])
                del p["age"]

        pdu_list = [
            self.event_from_pdu_json(p) for p in transaction.pdus
        ]

        logger.debug("[%s] Got transaction", transaction.transaction_id)

        response = yield self.transaction_actions.have_responded(transaction)

        if response:
            logger.debug(
                "[%s] We've already responded to this request",
                transaction.transaction_id
            )
            defer.returnValue(response)
            return

        logger.debug("[%s] Transaction is new", transaction.transaction_id)

        results = []

        for pdu in pdu_list:
            # check that it's actually being sent from a valid destination to
            # workaround bug #1753 in 0.18.5 and 0.18.6
            if transaction.origin != get_domain_from_id(pdu.event_id):
                if not (
                    pdu.type == 'm.room.member' and
                    pdu.content and
                    pdu.content.get("membership", None) == 'join' and
                    self.hs.is_mine_id(pdu.state_key)
                ):
                    logger.info(
                        "Discarding PDU %s from invalid origin %s",
                        pdu.event_id, transaction.origin
                    )
                    continue
                else:
                    logger.info(
                        "Accepting join PDU %s from %s",
                        pdu.event_id, transaction.origin
                    )

            try:
                yield self._handle_new_pdu(transaction.origin, pdu)
                results.append({})
            except FederationError as e:
                self.send_failure(e, transaction.origin)
                results.append({"error": str(e)})
            except Exception as e:
                results.append({"error": str(e)})
                logger.exception("Failed to handle PDU")

        if hasattr(transaction, "edus"):
            for edu in (Edu(**x) for x in transaction.edus):
                yield self.received_edu(
                    transaction.origin,
                    edu.edu_type,
                    edu.content
                )

            for failure in getattr(transaction, "pdu_failures", []):
                logger.info("Got failure %r", failure)

        logger.debug("Returning: %s", str(results))

        response = {
            "pdus": dict(zip(
                (p.event_id for p in pdu_list), results
            )),
        }

        yield self.transaction_actions.set_response(
            transaction,
            200, response
        )
        defer.returnValue((200, response))

    @defer.inlineCallbacks
    def received_edu(self, origin, edu_type, content):
        received_edus_counter.inc()

        if edu_type in self.edu_handlers:
            try:
                yield self.edu_handlers[edu_type](origin, content)
            except SynapseError as e:
                logger.info("Failed to handle edu %r: %r", edu_type, e)
            except Exception as e:
                logger.exception("Failed to handle edu %r", edu_type)
        else:
            logger.warn("Received EDU of type %s with no handler", edu_type)

    @defer.inlineCallbacks
    @log_function
    def on_context_state_request(self, origin, room_id, event_id):
        if not event_id:
            raise NotImplementedError("Specify an event")

        in_room = yield self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        result = self._state_resp_cache.get((room_id, event_id))
        if not result:
            with (yield self._server_linearizer.queue((origin, room_id))):
                resp = yield self._state_resp_cache.set(
                    (room_id, event_id),
                    self._on_context_state_request_compute(room_id, event_id)
                )
        else:
            resp = yield result

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_state_ids_request(self, origin, room_id, event_id):
        if not event_id:
            raise NotImplementedError("Specify an event")

        in_room = yield self.auth.check_host_in_room(room_id, origin)
        if not in_room:
            raise AuthError(403, "Host not in room.")

        state_ids = yield self.handler.get_state_ids_for_pdu(
            room_id, event_id,
        )
        auth_chain_ids = yield self.store.get_auth_chain_ids(state_ids)

        defer.returnValue((200, {
            "pdu_ids": state_ids,
            "auth_chain_ids": auth_chain_ids,
        }))

    @defer.inlineCallbacks
    def _on_context_state_request_compute(self, room_id, event_id):
        pdus = yield self.handler.get_state_for_pdu(
            room_id, event_id,
        )
        auth_chain = yield self.store.get_auth_chain(
            [pdu.event_id for pdu in pdus]
        )

        for event in auth_chain:
            # We sign these again because there was a bug where we
            # incorrectly signed things the first time round
            if self.hs.is_mine_id(event.event_id):
                event.signatures.update(
                    compute_event_signature(
                        event,
                        self.hs.hostname,
                        self.hs.config.signing_key[0]
                    )
                )

        defer.returnValue({
            "pdus": [pdu.get_pdu_json() for pdu in pdus],
            "auth_chain": [pdu.get_pdu_json() for pdu in auth_chain],
        })

    @defer.inlineCallbacks
    @log_function
    def on_pdu_request(self, origin, event_id):
        pdu = yield self._get_persisted_pdu(origin, event_id)

        if pdu:
            defer.returnValue(
                (200, self._transaction_from_pdus([pdu]).get_dict())
            )
        else:
            defer.returnValue((404, ""))

    @defer.inlineCallbacks
    @log_function
    def on_pull_request(self, origin, versions):
        raise NotImplementedError("Pull transactions not implemented")

    @defer.inlineCallbacks
    def on_query_request(self, query_type, args):
        received_queries_counter.inc(query_type)

        if query_type in self.query_handlers:
            response = yield self.query_handlers[query_type](args)
            defer.returnValue((200, response))
        else:
            defer.returnValue(
                (404, "No handler for Query type '%s'" % (query_type,))
            )

    @defer.inlineCallbacks
    def on_make_join_request(self, room_id, user_id):
        pdu = yield self.handler.on_make_join_request(room_id, user_id)
        time_now = self._clock.time_msec()
        defer.returnValue({"event": pdu.get_pdu_json(time_now)})

    @defer.inlineCallbacks
    def on_invite_request(self, origin, content):
        pdu = self.event_from_pdu_json(content)
        ret_pdu = yield self.handler.on_invite_request(origin, pdu)
        time_now = self._clock.time_msec()
        defer.returnValue((200, {"event": ret_pdu.get_pdu_json(time_now)}))

    @defer.inlineCallbacks
    def on_send_join_request(self, origin, content):
        logger.debug("on_send_join_request: content: %s", content)
        pdu = self.event_from_pdu_json(content)
        logger.debug("on_send_join_request: pdu sigs: %s", pdu.signatures)
        res_pdus = yield self.handler.on_send_join_request(origin, pdu)
        time_now = self._clock.time_msec()
        defer.returnValue((200, {
            "state": [p.get_pdu_json(time_now) for p in res_pdus["state"]],
            "auth_chain": [
                p.get_pdu_json(time_now) for p in res_pdus["auth_chain"]
            ],
        }))

    @defer.inlineCallbacks
    def on_make_leave_request(self, room_id, user_id):
        pdu = yield self.handler.on_make_leave_request(room_id, user_id)
        time_now = self._clock.time_msec()
        defer.returnValue({"event": pdu.get_pdu_json(time_now)})

    @defer.inlineCallbacks
    def on_send_leave_request(self, origin, content):
        logger.debug("on_send_leave_request: content: %s", content)
        pdu = self.event_from_pdu_json(content)
        logger.debug("on_send_leave_request: pdu sigs: %s", pdu.signatures)
        yield self.handler.on_send_leave_request(origin, pdu)
        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def on_event_auth(self, origin, room_id, event_id):
        with (yield self._server_linearizer.queue((origin, room_id))):
            time_now = self._clock.time_msec()
            auth_pdus = yield self.handler.on_event_auth(event_id)
            res = {
                "auth_chain": [a.get_pdu_json(time_now) for a in auth_pdus],
            }
        defer.returnValue((200, res))

    @defer.inlineCallbacks
    def on_query_auth_request(self, origin, content, room_id, event_id):
        """
        Content is a dict with keys::
            auth_chain (list): A list of events that give the auth chain.
            missing (list): A list of event_ids indicating what the other
              side (`origin`) think we're missing.
            rejects (dict): A mapping from event_id to a 2-tuple of reason
              string and a proof (or None) of why the event was rejected.
              The keys of this dict give the list of events the `origin` has
              rejected.

        Args:
            origin (str)
            content (dict)
            event_id (str)

        Returns:
            Deferred: Results in `dict` with the same format as `content`
        """
        with (yield self._server_linearizer.queue((origin, room_id))):
            auth_chain = [
                self.event_from_pdu_json(e)
                for e in content["auth_chain"]
            ]

            signed_auth = yield self._check_sigs_and_hash_and_fetch(
                origin, auth_chain, outlier=True
            )

            ret = yield self.handler.on_query_auth(
                origin,
                event_id,
                signed_auth,
                content.get("rejects", []),
                content.get("missing", []),
            )

            time_now = self._clock.time_msec()
            send_content = {
                "auth_chain": [
                    e.get_pdu_json(time_now)
                    for e in ret["auth_chain"]
                ],
                "rejects": ret.get("rejects", []),
                "missing": ret.get("missing", []),
            }

        defer.returnValue(
            (200, send_content)
        )

    @log_function
    def on_query_client_keys(self, origin, content):
        return self.on_query_request("client_keys", content)

    def on_query_user_devices(self, origin, user_id):
        return self.on_query_request("user_devices", user_id)

    @defer.inlineCallbacks
    @log_function
    def on_claim_client_keys(self, origin, content):
        query = []
        for user_id, device_keys in content.get("one_time_keys", {}).items():
            for device_id, algorithm in device_keys.items():
                query.append((user_id, device_id, algorithm))

        results = yield self.store.claim_e2e_one_time_keys(query)

        json_result = {}
        for user_id, device_keys in results.items():
            for device_id, keys in device_keys.items():
                for key_id, json_bytes in keys.items():
                    json_result.setdefault(user_id, {})[device_id] = {
                        key_id: json.loads(json_bytes)
                    }

        defer.returnValue({"one_time_keys": json_result})

    @defer.inlineCallbacks
    @log_function
    def on_get_missing_events(self, origin, room_id, earliest_events,
                              latest_events, limit, min_depth):
        with (yield self._server_linearizer.queue((origin, room_id))):
            logger.info(
                "on_get_missing_events: earliest_events: %r, latest_events: %r,"
                " limit: %d, min_depth: %d",
                earliest_events, latest_events, limit, min_depth
            )

            missing_events = yield self.handler.on_get_missing_events(
                origin, room_id, earliest_events, latest_events, limit, min_depth
            )

            if len(missing_events) < 5:
                logger.info(
                    "Returning %d events: %r", len(missing_events), missing_events
                )
            else:
                logger.info("Returning %d events", len(missing_events))

            time_now = self._clock.time_msec()

        defer.returnValue({
            "events": [ev.get_pdu_json(time_now) for ev in missing_events],
        })

    @log_function
    def on_openid_userinfo(self, token):
        ts_now_ms = self._clock.time_msec()
        return self.store.get_user_id_for_open_id_token(token, ts_now_ms)

    @log_function
    def _get_persisted_pdu(self, origin, event_id, do_auth=True):
        """ Get a PDU from the database with given origin and id.

        Returns:
            Deferred: Results in a `Pdu`.
        """
        return self.handler.get_persisted_pdu(
            origin, event_id, do_auth=do_auth
        )

    def _transaction_from_pdus(self, pdu_list):
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

    @defer.inlineCallbacks
    @log_function
    def _handle_new_pdu(self, origin, pdu, get_missing=True):

        # We reprocess pdus when we have seen them only as outliers
        existing = yield self._get_persisted_pdu(
            origin, pdu.event_id, do_auth=False
        )

        # FIXME: Currently we fetch an event again when we already have it
        # if it has been marked as an outlier.

        already_seen = (
            existing and (
                not existing.internal_metadata.is_outlier()
                or pdu.internal_metadata.is_outlier()
            )
        )
        if already_seen:
            logger.debug("Already seen pdu %s", pdu.event_id)
            return

        # Check signature.
        try:
            pdu = yield self._check_sigs_and_hash(pdu)
        except SynapseError as e:
            raise FederationError(
                "ERROR",
                e.code,
                e.msg,
                affected=pdu.event_id,
            )

        state = None

        auth_chain = []

        have_seen = yield self.store.have_events(
            [ev for ev, _ in pdu.prev_events]
        )

        fetch_state = False

        # Get missing pdus if necessary.
        if not pdu.internal_metadata.is_outlier():
            # We only backfill backwards to the min depth.
            min_depth = yield self.handler.get_min_depth_for_context(
                pdu.room_id
            )

            logger.debug(
                "_handle_new_pdu min_depth for %s: %d",
                pdu.room_id, min_depth
            )

            prevs = {e_id for e_id, _ in pdu.prev_events}
            seen = set(have_seen.keys())

            if min_depth and pdu.depth < min_depth:
                # This is so that we don't notify the user about this
                # message, to work around the fact that some events will
                # reference really really old events we really don't want to
                # send to the clients.
                pdu.internal_metadata.outlier = True
            elif min_depth and pdu.depth > min_depth:
                if get_missing and prevs - seen:
                    # If we're missing stuff, ensure we only fetch stuff one
                    # at a time.
                    logger.info(
                        "Acquiring lock for room %r to fetch %d missing events: %r...",
                        pdu.room_id, len(prevs - seen), list(prevs - seen)[:5],
                    )
                    with (yield self._room_pdu_linearizer.queue(pdu.room_id)):
                        logger.info(
                            "Acquired lock for room %r to fetch %d missing events",
                            pdu.room_id, len(prevs - seen),
                        )

                        # We recalculate seen, since it may have changed.
                        have_seen = yield self.store.have_events(prevs)
                        seen = set(have_seen.keys())

                        if prevs - seen:
                            latest = yield self.store.get_latest_event_ids_in_room(
                                pdu.room_id
                            )

                            # We add the prev events that we have seen to the latest
                            # list to ensure the remote server doesn't give them to us
                            latest = set(latest)
                            latest |= seen

                            logger.info(
                                "Missing %d events for room %r: %r...",
                                len(prevs - seen), pdu.room_id, list(prevs - seen)[:5]
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

                            missing_events = yield self.get_missing_events(
                                origin,
                                pdu.room_id,
                                earliest_events_ids=list(latest),
                                latest_events=[pdu],
                                limit=10,
                                min_depth=min_depth,
                                timeout=10000,
                            )

                            # We want to sort these by depth so we process them and
                            # tell clients about them in order.
                            missing_events.sort(key=lambda x: x.depth)

                            for e in missing_events:
                                yield self._handle_new_pdu(
                                    origin,
                                    e,
                                    get_missing=False
                                )

                            have_seen = yield self.store.have_events(
                                [ev for ev, _ in pdu.prev_events]
                            )

            prevs = {e_id for e_id, _ in pdu.prev_events}
            seen = set(have_seen.keys())
            if prevs - seen:
                logger.info(
                    "Still missing %d events for room %r: %r...",
                    len(prevs - seen), pdu.room_id, list(prevs - seen)[:5]
                )
                fetch_state = True

        if fetch_state:
            # We need to get the state at this event, since we haven't
            # processed all the prev events.
            logger.debug(
                "_handle_new_pdu getting state for %s",
                pdu.room_id
            )
            try:
                state, auth_chain = yield self.get_state_for_room(
                    origin, pdu.room_id, pdu.event_id,
                )
            except:
                logger.exception("Failed to get state for event: %s", pdu.event_id)

        yield self.handler.on_receive_pdu(
            origin,
            pdu,
            state=state,
            auth_chain=auth_chain,
        )

    def __str__(self):
        return "<ReplicationLayer(%s)>" % self.server_name

    def event_from_pdu_json(self, pdu_json, outlier=False):
        event = FrozenEvent(
            pdu_json
        )

        event.internal_metadata.outlier = outlier

        return event

    @defer.inlineCallbacks
    def exchange_third_party_invite(
            self,
            sender_user_id,
            target_user_id,
            room_id,
            signed,
    ):
        ret = yield self.handler.exchange_third_party_invite(
            sender_user_id,
            target_user_id,
            room_id,
            signed,
        )
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def on_exchange_third_party_invite_request(self, origin, room_id, event_dict):
        ret = yield self.handler.on_exchange_third_party_invite_request(
            origin, room_id, event_dict
        )
        defer.returnValue(ret)
