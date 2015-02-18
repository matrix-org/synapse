# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.util.logutils import log_function
from synapse.util.logcontext import PreserveLoggingContext
from synapse.events import FrozenEvent

from synapse.api.errors import FederationError, SynapseError

from synapse.crypto.event_signing import compute_event_signature

import logging


logger = logging.getLogger(__name__)


class FederationServer(FederationBase):
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
        pdus = yield self.handler.on_backfill_request(
            origin, room_id, versions, limit
        )

        defer.returnValue((200, self._transaction_from_pdus(pdus).get_dict()))

    @defer.inlineCallbacks
    @log_function
    def on_incoming_transaction(self, transaction_data):
        transaction = Transaction(**transaction_data)

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
                "[%s] We've already responed to this request",
                transaction.transaction_id
            )
            defer.returnValue(response)
            return

        logger.debug("[%s] Transaction is new", transaction.transaction_id)

        with PreserveLoggingContext():
            dl = []
            for pdu in pdu_list:
                d = self._handle_new_pdu(transaction.origin, pdu)

                def handle_failure(failure):
                    failure.trap(FederationError)
                    self.send_failure(failure.value, transaction.origin)

                d.addErrback(handle_failure)

                dl.append(d)

            if hasattr(transaction, "edus"):
                for edu in [Edu(**x) for x in transaction.edus]:
                    self.received_edu(
                        transaction.origin,
                        edu.edu_type,
                        edu.content
                    )

            for failure in getattr(transaction, "pdu_failures", []):
                logger.info("Got failure %r", failure)

            results = yield defer.DeferredList(dl, consumeErrors=True)

        ret = []
        for r in results:
            if r[0]:
                ret.append({})
            else:
                logger.exception(r[1])
                ret.append({"error": str(r[1].value)})

        logger.debug("Returning: %s", str(ret))

        response = {
            "pdus": dict(zip(
                (p.event_id for p in pdu_list), ret
            )),
        }

        yield self.transaction_actions.set_response(
            transaction,
            200, response
        )
        defer.returnValue((200, response))

    def received_edu(self, origin, edu_type, content):
        if edu_type in self.edu_handlers:
            self.edu_handlers[edu_type](origin, content)
        else:
            logger.warn("Received EDU of type %s with no handler", edu_type)

    @defer.inlineCallbacks
    @log_function
    def on_context_state_request(self, origin, room_id, event_id):
        if event_id:
            pdus = yield self.handler.get_state_for_pdu(
                origin, room_id, event_id,
            )
            auth_chain = yield self.store.get_auth_chain(
                [pdu.event_id for pdu in pdus]
            )

            for event in auth_chain:
                event.signatures.update(
                    compute_event_signature(
                        event,
                        self.hs.hostname,
                        self.hs.config.signing_key[0]
                    )
                )
        else:
            raise NotImplementedError("Specify an event")

        defer.returnValue((200, {
            "pdus": [pdu.get_pdu_json() for pdu in pdus],
            "auth_chain": [pdu.get_pdu_json() for pdu in auth_chain],
        }))

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
    def on_event_auth(self, origin, room_id, event_id):
        time_now = self._clock.time_msec()
        auth_pdus = yield self.handler.on_event_auth(event_id)
        defer.returnValue((200, {
            "auth_chain": [a.get_pdu_json(time_now) for a in auth_pdus],
        }))

    @defer.inlineCallbacks
    def on_query_auth_request(self, origin, content, event_id):
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
    def _handle_new_pdu(self, origin, pdu, max_recursion=10):
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

            if min_depth and pdu.depth < min_depth:
                # This is so that we don't notify the user about this
                # message, to work around the fact that some events will
                # reference really really old events we really don't want to
                # send to the clients.
                pdu.internal_metadata.outlier = True
            elif min_depth and pdu.depth > min_depth and max_recursion > 0:
                for event_id, hashes in pdu.prev_events:
                    if event_id not in have_seen:
                        logger.debug(
                            "_handle_new_pdu requesting pdu %s",
                            event_id
                        )

                        try:
                            new_pdu = yield self.federation_client.get_pdu(
                                [origin, pdu.origin],
                                event_id=event_id,
                            )

                            if new_pdu:
                                yield self._handle_new_pdu(
                                    origin,
                                    new_pdu,
                                    max_recursion=max_recursion-1
                                )

                                logger.debug("Processed pdu %s", event_id)
                            else:
                                logger.warn("Failed to get PDU %s", event_id)
                                fetch_state = True
                        except:
                            # TODO(erikj): Do some more intelligent retries.
                            logger.exception("Failed to get PDU")
                            fetch_state = True
            else:
                prevs = {e_id for e_id, _ in pdu.prev_events}
                seen = set(have_seen.keys())
                if prevs - seen:
                    fetch_state = True
        else:
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
                logger.warn("Failed to get state for event: %s", pdu.event_id)

        yield self.handler.on_receive_pdu(
            origin,
            pdu,
            backfilled=False,
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
