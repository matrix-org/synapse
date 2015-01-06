# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

logger = logging.getLogger(__name__)


# FIXME: elsewhere we use FooStore to indicate something in the storage layer...
class HttpTransactionStore(object):

    def __init__(self):
        # { key : (txn_id, response) }
        self.transactions = {}

    def get_response(self, key, txn_id):
        """Retrieve a response for this request.

        Args:
            key (str): A transaction-independent key for this request. Usually
                this is a combination of the path (without the transaction id)
                and the user's access token.
            txn_id (str): The transaction ID for this request
        Returns:
            A tuple of (HTTP response code, response content) or None.
        """
        try:
            logger.debug("get_response Key: %s TxnId: %s", key, txn_id)
            (last_txn_id, response) = self.transactions[key]
            if txn_id == last_txn_id:
                logger.info("get_response: Returning a response for %s", key)
                return response
        except KeyError:
            pass
        return None

    def store_response(self, key, txn_id, response):
        """Stores an HTTP response tuple.

        Args:
            key (str): A transaction-independent key for this request. Usually
                this is a combination of the path (without the transaction id)
                and the user's access token.
            txn_id (str): The transaction ID for this request.
            response (tuple): A tuple of (HTTP response code, response content)
        """
        logger.debug("store_response Key: %s TxnId: %s", key, txn_id)
        self.transactions[key] = (txn_id, response)

    def store_client_transaction(self, request, txn_id, response):
        """Stores the request/response pair of an HTTP transaction.

        Args:
            request (twisted.web.http.Request): The twisted HTTP request. This
            request must have the transaction ID as the last path segment.
            response (tuple): A tuple of (response code, response dict)
            txn_id (str): The transaction ID for this request.
        """
        self.store_response(self._get_key(request), txn_id, response)

    def get_client_transaction(self, request, txn_id):
        """Retrieves a stored response if there was one.

        Args:
            request (twisted.web.http.Request): The twisted HTTP request. This
            request must have the transaction ID as the last path segment.
            txn_id (str): The transaction ID for this request.
        Returns:
            The response tuple.
        Raises:
            KeyError if the transaction was not found.
        """
        response = self.get_response(self._get_key(request), txn_id)
        if response is None:
            raise KeyError("Transaction not found.")
        return response

    def _get_key(self, request):
        token = request.args["access_token"][0]
        path_without_txn_id = request.path.rsplit("/", 1)[0]
        return path_without_txn_id + "/" + token
