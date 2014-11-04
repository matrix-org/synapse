# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

"""This layer is responsible for replicating with remote home servers using
a given transport.
"""

from twisted.internet import defer

from .units import Transaction, Pdu, Edu

from .persistence import TransactionActions

from synapse.util.logutils import log_function

import logging


logger = logging.getLogger(__name__)


class ReplicationLayer(object):
    """This layer is responsible for replicating with remote home servers over
    the given transport. I.e., does the sending and receiving of PDUs to
    remote home servers.

    The layer communicates with the rest of the server via a registered
    ReplicationHandler.

    In more detail, the layer:
        * Receives incoming data and processes it into transactions and pdus.
        * Fetches any PDUs it thinks it might have missed.
        * Keeps the current state for contexts up to date by applying the
          suitable conflict resolution.
        * Sends outgoing pdus wrapped in transactions.
        * Fills out the references to previous pdus/transactions appropriately
          for outgoing data.
    """

    def __init__(self, hs, transport_layer):
        self.server_name = hs.hostname

        self.transport_layer = transport_layer
        self.transport_layer.register_received_handler(self)
        self.transport_layer.register_request_handler(self)

        self.store = hs.get_datastore()
        # self.pdu_actions = PduActions(self.store)
        self.transaction_actions = TransactionActions(self.store)

        self._transaction_queue = _TransactionQueue(
            hs, self.transaction_actions, transport_layer
        )

        self.handler = None
        self.edu_handlers = {}
        self.query_handlers = {}

        self._order = 0

        self._clock = hs.get_clock()

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

    @log_function
    def send_pdu(self, pdu):
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

        logger.debug("[%s] transaction_layer.enqueue_pdu... ", pdu.event_id)

        # TODO, add errback, etc.
        self._transaction_queue.enqueue_pdu(pdu, order)

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

        # TODO, add errback, etc.
        self._transaction_queue.enqueue_edu(edu)
        return defer.succeed(None)

    @log_function
    def send_failure(self, failure, destination):
        self._transaction_queue.enqueue_failure(failure, destination)
        return defer.succeed(None)

    @log_function
    def make_query(self, destination, query_type, args,
                   retry_on_dns_fail=True):
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
        return self.transport_layer.make_query(
            destination, query_type, args, retry_on_dns_fail=retry_on_dns_fail
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

        transaction = Transaction(**transaction_data)

        pdus = [Pdu(outlier=False, **p) for p in transaction.pdus]
        for pdu in pdus:
            yield self._handle_new_pdu(pdu, backfilled=True)

        defer.returnValue(pdus)

    @defer.inlineCallbacks
    @log_function
    def get_pdu(self, destination, event_id, outlier=False):
        """Requests the PDU with given origin and ID from the remote home
        server.

        This will persist the PDU locally upon receipt.

        Args:
            destination (str): Which home server to query
            pdu_origin (str): The home server that originally sent the pdu.
            event_id (str)
            outlier (bool): Indicates whether the PDU is an `outlier`, i.e. if
                it's from an arbitary point in the context as opposed to part
                of the current block of PDUs. Defaults to `False`

        Returns:
            Deferred: Results in the requested PDU.
        """

        transaction_data = yield self.transport_layer.get_event(
            destination, event_id
        )

        transaction = Transaction(**transaction_data)

        pdu_list = [Pdu(outlier=outlier, **p) for p in transaction.pdus]

        pdu = None
        if pdu_list:
            pdu = pdu_list[0]
            yield self._handle_new_pdu(destination, pdu)

        defer.returnValue(pdu)

    @defer.inlineCallbacks
    @log_function
    def get_state_for_context(self, destination, context, event_id=None):
        """Requests all of the `current` state PDUs for a given context from
        a remote home server.

        Args:
            destination (str): The remote homeserver to query for the state.
            context (str): The context we're interested in.

        Returns:
            Deferred: Results in a list of PDUs.
        """

        transaction_data = yield self.transport_layer.get_context_state(
            destination,
            context,
            event_id=event_id,
        )

        transaction = Transaction(**transaction_data)

        pdus = [Pdu(outlier=True, **p) for p in transaction.pdus]
        for pdu in pdus:
            yield self._handle_new_pdu(destination, pdu)

        defer.returnValue(pdus)

    @defer.inlineCallbacks
    @log_function
    def on_context_pdus_request(self, context):
        raise NotImplementedError(
            "on_context_pdus_request is a security violation"
        )

    @defer.inlineCallbacks
    @log_function
    def on_backfill_request(self, context, versions, limit):
        pdus = yield self.handler.on_backfill_request(
            context, versions, limit
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

        pdu_list = [Pdu(**p) for p in transaction.pdus]

        logger.debug("[%s] Got transaction", transaction.transaction_id)

        response = yield self.transaction_actions.have_responded(transaction)

        if response:
            logger.debug("[%s] We've already responed to this request",
                         transaction.transaction_id)
            defer.returnValue(response)
            return

        logger.debug("[%s] Transacition is new", transaction.transaction_id)

        dl = []
        for pdu in pdu_list:
            dl.append(self._handle_new_pdu(transaction.origin, pdu))

        if hasattr(transaction, "edus"):
            for edu in [Edu(**x) for x in transaction.edus]:
                self.received_edu(
                    transaction.origin,
                    edu.edu_type,
                    edu.content
                )

        results = yield defer.DeferredList(dl)

        ret = []
        for r in results:
            if r[0]:
                ret.append({})
            else:
                logger.exception(r[1])
                ret.append({"error": str(r[1])})

        logger.debug("Returning: %s", str(ret))

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
    def on_context_state_request(self, context, event_id):
        if event_id:
            pdus = yield self.handler.get_state_for_pdu(
                event_id
            )
        else:
            raise NotImplementedError("Specify an event")
        #     results = yield self.store.get_current_state_for_context(
        #         context
        #     )
        #     pdus = [Pdu.from_pdu_tuple(p) for p in results]
        #
        # logger.debug("Context returning %d results", len(pdus))

        defer.returnValue((200, self._transaction_from_pdus(pdus).get_dict()))

    @defer.inlineCallbacks
    @log_function
    def on_pdu_request(self, event_id):
        pdu = yield self._get_persisted_pdu(event_id)

        if pdu:
            defer.returnValue(
                (200, self._transaction_from_pdus([pdu]).get_dict())
            )
        else:
            defer.returnValue((404, ""))

    @defer.inlineCallbacks
    @log_function
    def on_pull_request(self, origin, versions):
        raise NotImplementedError("Pull transacions not implemented")

        # transaction_id = max([int(v) for v in versions])
        #
        # response = yield self.pdu_actions.after_transaction(
        #     transaction_id,
        #     origin,
        #     self.server_name
        # )
        #
        # if not response:
        #     response = []
        #
        # defer.returnValue(
        #     (200, self._transaction_from_pdus(response).get_dict())
        # )

    @defer.inlineCallbacks
    def on_query_request(self, query_type, args):
        if query_type in self.query_handlers:
            response = yield self.query_handlers[query_type](args)
            defer.returnValue((200, response))
        else:
            defer.returnValue(
                (404, "No handler for Query type '%s'" % (query_type, ))
            )

    @defer.inlineCallbacks
    def on_make_join_request(self, context, user_id):
        pdu = yield self.handler.on_make_join_request(context, user_id)
        defer.returnValue(pdu.get_dict())

    @defer.inlineCallbacks
    def on_invite_request(self, origin, content):
        pdu = Pdu(**content)
        ret_pdu = yield self.handler.on_send_join_request(origin, pdu)
        defer.returnValue((200, ret_pdu.get_dict()))

    @defer.inlineCallbacks
    def on_send_join_request(self, origin, content):
        pdu = Pdu(**content)
        state = yield self.handler.on_send_join_request(origin, pdu)
        defer.returnValue((200, self._transaction_from_pdus(state).get_dict()))

    @defer.inlineCallbacks
    def make_join(self, destination, context, user_id):
        pdu_dict = yield self.transport_layer.make_join(
            destination=destination,
            context=context,
            user_id=user_id,
        )

        logger.debug("Got response to make_join: %s", pdu_dict)

        defer.returnValue(Pdu(**pdu_dict))

    @defer.inlineCallbacks
    def send_join(self, destination, pdu):
        _, content = yield self.transport_layer.send_join(
            destination,
            pdu.room_id,
            pdu.event_id,
            pdu.get_dict(),
        )

        logger.debug("Got content: %s", content)
        pdus = [Pdu(outlier=True, **p) for p in content.get("pdus", [])]
        for pdu in pdus:
            yield self._handle_new_pdu(destination, pdu)

        defer.returnValue(pdus)

    @log_function
    def _get_persisted_pdu(self, event_id):
        """ Get a PDU from the database with given origin and id.

        Returns:
            Deferred: Results in a `Pdu`.
        """
        return self.handler.get_persisted_pdu(event_id)

    def _transaction_from_pdus(self, pdu_list):
        """Returns a new Transaction containing the given PDUs suitable for
        transmission.
        """
        pdus = [p.get_dict() for p in pdu_list]
        time_now = self._clock.time_msec()
        for p in pdus:
            if "age_ts" in p:
                age = time_now - p["age_ts"]
                p.setdefault("unsigned", {})["age"] = int(age)
                del p["age_ts"]
        return Transaction(
            origin=self.server_name,
            pdus=pdus,
            origin_server_ts=int(time_now),
            destination=None,
        )

    @defer.inlineCallbacks
    @log_function
    def _handle_new_pdu(self, origin, pdu, backfilled=False):
        # We reprocess pdus when we have seen them only as outliers
        existing = yield self._get_persisted_pdu(pdu.event_id)

        if existing and (not existing.outlier or pdu.outlier):
            logger.debug("Already seen pdu %s", pdu.event_id)
            defer.returnValue({})
            return

        state = None

        # Get missing pdus if necessary.
        if not pdu.outlier:
            # We only backfill backwards to the min depth.
            min_depth = yield self.handler.get_min_depth_for_context(
                pdu.room_id
            )

            if min_depth and pdu.depth > min_depth:
                for event_id, hashes in pdu.prev_events:
                    exists = yield self._get_persisted_pdu(event_id)

                    if not exists:
                        logger.debug("Requesting pdu %s", event_id)

                        try:
                            yield self.get_pdu(
                                pdu.origin,
                                event_id=event_id,
                            )
                            logger.debug("Processed pdu %s", event_id)
                        except:
                            # TODO(erikj): Do some more intelligent retries.
                            logger.exception("Failed to get PDU")
            else:
                # We need to get the state at this event, since we have reached
                # a backward extremity edge.
                state = yield self.get_state_for_context(
                    origin, pdu.room_id, pdu.event_id,
                )

        # Persist the Pdu, but don't mark it as processed yet.
        # yield self.store.persist_event(pdu=pdu)

        if not backfilled:
            ret = yield self.handler.on_receive_pdu(
                pdu,
                backfilled=backfilled,
                state=state,
            )
        else:
            ret = None

        # yield self.pdu_actions.mark_as_processed(pdu)

        defer.returnValue(ret)

    def __str__(self):
        return "<ReplicationLayer(%s)>" % self.server_name


class _TransactionQueue(object):
    """This class makes sure we only have one transaction in flight at
    a time for a given destination.

    It batches pending PDUs into single transactions.
    """

    def __init__(self, hs, transaction_actions, transport_layer):
        self.server_name = hs.hostname
        self.transaction_actions = transaction_actions
        self.transport_layer = transport_layer

        self._clock = hs.get_clock()

        # Is a mapping from destinations -> deferreds. Used to keep track
        # of which destinations have transactions in flight and when they are
        # done
        self.pending_transactions = {}

        # Is a mapping from destination -> list of
        # tuple(pending pdus, deferred, order)
        self.pending_pdus_by_dest = {}
        # destination -> list of tuple(edu, deferred)
        self.pending_edus_by_dest = {}

        # destination -> list of tuple(failure, deferred)
        self.pending_failures_by_dest = {}

        # HACK to get unique tx id
        self._next_txn_id = int(self._clock.time_msec())

    @defer.inlineCallbacks
    @log_function
    def enqueue_pdu(self, pdu, order):
        # We loop through all destinations to see whether we already have
        # a transaction in progress. If we do, stick it in the pending_pdus
        # table and we'll get back to it later.

        destinations = set([
            d for d in pdu.destinations
            if d != self.server_name
        ])

        logger.debug("Sending to: %s", str(destinations))

        if not destinations:
            return

        deferreds = []

        for destination in destinations:
            deferred = defer.Deferred()
            self.pending_pdus_by_dest.setdefault(destination, []).append(
                (pdu, deferred, order)
            )

            self._attempt_new_transaction(destination)

            deferreds.append(deferred)

        yield defer.DeferredList(deferreds)

    # NO inlineCallbacks
    def enqueue_edu(self, edu):
        destination = edu.destination

        deferred = defer.Deferred()
        self.pending_edus_by_dest.setdefault(destination, []).append(
            (edu, deferred)
        )

        def eb(failure):
            if not deferred.called:
                deferred.errback(failure)
            else:
                logger.exception("Failed to send edu", failure)
        self._attempt_new_transaction(destination).addErrback(eb)

        return deferred

    @defer.inlineCallbacks
    def enqueue_failure(self, failure, destination):
        deferred = defer.Deferred()

        self.pending_failures_by_dest.setdefault(
            destination, []
        ).append(
            (failure, deferred)
        )

        yield deferred

    @defer.inlineCallbacks
    @log_function
    def _attempt_new_transaction(self, destination):
        if destination in self.pending_transactions:
            return

        #  list of (pending_pdu, deferred, order)
        pending_pdus = self.pending_pdus_by_dest.pop(destination, [])
        pending_edus = self.pending_edus_by_dest.pop(destination, [])
        pending_failures = self.pending_failures_by_dest.pop(destination, [])

        if not pending_pdus and not pending_edus and not pending_failures:
            return

        logger.debug("TX [%s] Attempting new transaction", destination)

        # Sort based on the order field
        pending_pdus.sort(key=lambda t: t[2])

        pdus = [x[0] for x in pending_pdus]
        edus = [x[0] for x in pending_edus]
        failures = [x[0].get_dict() for x in pending_failures]
        deferreds = [
            x[1]
            for x in pending_pdus + pending_edus + pending_failures
        ]

        try:
            self.pending_transactions[destination] = 1

            logger.debug("TX [%s] Persisting transaction...", destination)

            transaction = Transaction.create_new(
                origin_server_ts=int(self._clock.time_msec()),
                transaction_id=str(self._next_txn_id),
                origin=self.server_name,
                destination=destination,
                pdus=pdus,
                edus=edus,
                pdu_failures=failures,
            )

            self._next_txn_id += 1

            yield self.transaction_actions.prepare_to_send(transaction)

            logger.debug("TX [%s] Persisted transaction", destination)
            logger.debug("TX [%s] Sending transaction...", destination)

            # Actually send the transaction

            # FIXME (erikj): This is a bit of a hack to make the Pdu age
            # keys work
            def json_data_cb():
                data = transaction.get_dict()
                now = int(self._clock.time_msec())
                if "pdus" in data:
                    for p in data["pdus"]:
                        if "age_ts" in p:
                            unsigned = p.setdefault("unsigned", {})
                            unsigned["age"] = now - int(p["age_ts"])
                            del p["age_ts"]
                return data

            code, response = yield self.transport_layer.send_transaction(
                transaction, json_data_cb
            )

            logger.debug("TX [%s] Sent transaction", destination)
            logger.debug("TX [%s] Marking as delivered...", destination)

            yield self.transaction_actions.delivered(
                transaction, code, response
            )

            logger.debug("TX [%s] Marked as delivered", destination)
            logger.debug("TX [%s] Yielding to callbacks...", destination)

            for deferred in deferreds:
                if code == 200:
                    deferred.callback(None)
                else:
                    deferred.errback(RuntimeError("Got status %d" % code))

                # Ensures we don't continue until all callbacks on that
                # deferred have fired
                yield deferred

            logger.debug("TX [%s] Yielded to callbacks", destination)

        except Exception as e:
            logger.error("TX Problem in _attempt_transaction")

            # We capture this here as there as nothing actually listens
            # for this finishing functions deferred.
            logger.exception(e)

            for deferred in deferreds:
                deferred.errback(e)

        finally:
            # We want to be *very* sure we delete this after we stop processing
            self.pending_transactions.pop(destination, None)

            # Check to see if there is anything else to send.
            self._attempt_new_transaction(destination)
