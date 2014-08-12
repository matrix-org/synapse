# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
""" This module contains all the persistence actions done by the federation
package.

These actions are mostly only used by the :py:mod:`.replication` module.
"""

from twisted.internet import defer

from .units import Pdu

from synapse.util.logutils import log_function

import copy
import json
import logging


logger = logging.getLogger(__name__)


class PduActions(object):
    """ Defines persistence actions that relate to handling PDUs.
    """

    def __init__(self, datastore):
        self.store = datastore

    @log_function
    def persist_received(self, pdu):
        """ Persists the given `Pdu` that was received from a remote home
        server.

        Returns:
            Deferred
        """
        return self._persist(pdu)

    @defer.inlineCallbacks
    @log_function
    def persist_outgoing(self, pdu):
        """ Persists the given `Pdu` that this home server created.

        Returns:
            Deferred
        """
        ret = yield self._persist(pdu)

        defer.returnValue(ret)

    @log_function
    def mark_as_processed(self, pdu):
        """ Persist the fact that we have fully processed the given `Pdu`

        Returns:
            Deferred
        """
        return self.store.mark_pdu_as_processed(pdu.pdu_id, pdu.origin)

    @defer.inlineCallbacks
    @log_function
    def populate_previous_pdus(self, pdu):
        """ Given an outgoing `Pdu` fill out its `prev_ids` key with the `Pdu`s
        that we have received.

        Returns:
            Deferred
        """
        results = yield self.store.get_latest_pdus_in_context(pdu.context)

        pdu.prev_pdus = [(p_id, origin) for p_id, origin, _ in results]

        vs = [int(v) for _, _, v in results]
        if vs:
            pdu.depth = max(vs) + 1
        else:
            pdu.depth = 0

    @defer.inlineCallbacks
    @log_function
    def after_transaction(self, transaction_id, destination, origin):
        """ Returns all `Pdu`s that we sent to the given remote home server
        after a given transaction id.

        Returns:
            Deferred: Results in a list of `Pdu`s
        """
        results = yield self.store.get_pdus_after_transaction(
            transaction_id,
            destination
        )

        defer.returnValue([Pdu.from_pdu_tuple(p) for p in results])

    @defer.inlineCallbacks
    @log_function
    def get_all_pdus_from_context(self, context):
        results = yield self.store.get_all_pdus_from_context(context)
        defer.returnValue([Pdu.from_pdu_tuple(p) for p in results])

    @defer.inlineCallbacks
    @log_function
    def paginate(self, context, pdu_list, limit):
        """ For a given list of PDU id and origins return the proceeding
        `limit` `Pdu`s in the given `context`.

        Returns:
            Deferred: Results in a list of `Pdu`s.
        """
        results = yield self.store.get_pagination(
            context, pdu_list, limit
        )

        defer.returnValue([Pdu.from_pdu_tuple(p) for p in results])

    @log_function
    def is_new(self, pdu):
        """ When we receive a `Pdu` from a remote home server, we want to
        figure out whether it is `new`, i.e. it is not some historic PDU that
        we haven't seen simply because we haven't paginated back that far.

        Returns:
            Deferred: Results in a `bool`
        """
        return self.store.is_pdu_new(
            pdu_id=pdu.pdu_id,
            origin=pdu.origin,
            context=pdu.context,
            depth=pdu.depth
        )

    @defer.inlineCallbacks
    @log_function
    def _persist(self, pdu):
        kwargs = copy.copy(pdu.__dict__)
        unrec_keys = copy.copy(pdu.unrecognized_keys)
        del kwargs["content"]
        kwargs["content_json"] = json.dumps(pdu.content)
        kwargs["unrecognized_keys"] = json.dumps(unrec_keys)

        logger.debug("Persisting: %s", repr(kwargs))

        if pdu.is_state:
            ret = yield self.store.persist_state(**kwargs)
        else:
            ret = yield self.store.persist_pdu(**kwargs)

        yield self.store.update_min_depth_for_context(
            pdu.context, pdu.depth
        )

        defer.returnValue(ret)


class TransactionActions(object):
    """ Defines persistence actions that relate to handling Transactions.
    """

    def __init__(self, datastore):
        self.store = datastore

    @log_function
    def have_responded(self, transaction):
        """ Have we already responded to a transaction with the same id and
        origin?

        Returns:
            Deferred: Results in `None` if we have not previously responded to
            this transaction or a 2-tuple of `(int, dict)` representing the
            response code and response body.
        """
        if not transaction.transaction_id:
            raise RuntimeError("Cannot persist a transaction with no "
                               "transaction_id")

        return self.store.get_received_txn_response(
            transaction.transaction_id, transaction.origin
        )

    @log_function
    def set_response(self, transaction, code, response):
        """ Persist how we responded to a transaction.

        Returns:
            Deferred
        """
        if not transaction.transaction_id:
            raise RuntimeError("Cannot persist a transaction with no "
                               "transaction_id")

        return self.store.set_received_txn_response(
            transaction.transaction_id,
            transaction.origin,
            code,
            json.dumps(response)
        )

    @defer.inlineCallbacks
    @log_function
    def prepare_to_send(self, transaction):
        """ Persists the `Transaction` we are about to send and works out the
        correct value for the `prev_ids` key.

        Returns:
            Deferred
        """
        transaction.prev_ids = yield self.store.prep_send_transaction(
            transaction.transaction_id,
            transaction.destination,
            transaction.ts,
            [(p["pdu_id"], p["origin"]) for p in transaction.pdus]
        )

    @log_function
    def delivered(self, transaction, response_code, response_dict):
        """ Marks the given `Transaction` as having been successfully
        delivered to the remote homeserver, and what the response was.

        Returns:
            Deferred
        """
        return self.store.delivered_txn(
            transaction.transaction_id,
            transaction.destination,
            response_code,
            json.dumps(response_dict)
        )
