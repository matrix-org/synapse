# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""This module contains logic for storing HTTP PUT transactions. This is used
to ensure idempotency when performing PUTs using the REST API."""
import logging

from synapse.api.auth import get_access_token_from_request

logger = logging.getLogger(__name__)


class HttpTransactionCache(object):

    def __init__(self):
        # { key : (txn_id, response_deferred) }
        self.transactions = {}

    def _get_response(self, key, txn_id):
        try:
            (last_txn_id, response_deferred) = self.transactions[key]
            if txn_id == last_txn_id:
                logger.info("get_response: Returning a response for %s", txn_id)
                return response_deferred
        except KeyError:
            pass
        return None

    def _store_response(self, key, txn_id, response_deferred):
        self.transactions[key] = (txn_id, response_deferred)

    def store_client_transaction(self, request, txn_id, response_deferred):
        """Stores the request/Promise<response> pair of an HTTP transaction.

        Args:
            request (twisted.web.http.Request): The twisted HTTP request. This
            request must have the transaction ID as the last path segment.
            response_deferred (Promise<tuple>): A tuple of (response code, response dict)
            txn_id (str): The transaction ID for this request.
        """
        self._store_response(self._get_key(request), txn_id, response_deferred)

    def get_client_transaction(self, request, txn_id):
        """Retrieves a stored response if there was one.

        Args:
            request (twisted.web.http.Request): The twisted HTTP request. This
            request must have the transaction ID as the last path segment.
            txn_id (str): The transaction ID for this request.
        Returns:
            Promise: Resolves to the response tuple.
        Raises:
            KeyError if the transaction was not found.
        """
        response_deferred = self._get_response(self._get_key(request), txn_id)
        if response_deferred is None:
            raise KeyError("Transaction not found.")
        return response_deferred

    def _get_key(self, request):
        token = get_access_token_from_request(request)
        path_without_txn_id = request.path.rsplit("/", 1)[0]
        return path_without_txn_id + "/" + token
