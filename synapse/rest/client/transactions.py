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
from synapse.util.async import ObservableDeferred

logger = logging.getLogger(__name__)


def get_transaction_key(request):
    """A helper function which returns a transaction key that can be used
    with TransactionCache for idempotent requests.

    Idempotency is based on the returned key being the same for separate
    requests to the same endpoint. The key is formed from the HTTP request
    path and the access_token for the requesting user.

    Args:
        request (twisted.web.http.Request): The incoming request. Must
        contain an access_token.
    Returns:
        str: A transaction key
    """
    token = get_access_token_from_request(request)
    return request.path + "/" + token


CLEANUP_PERIOD_MS = 1000 * 60 * 30  # 30 mins


class HttpTransactionCache(object):

    def __init__(self, clock):
        self.clock = clock
        self.transactions = {
            # $txn_key: (ObservableDeferred<(res_code, res_json_body)>, timestamp)
        }
        # Try to clean entries every 30 mins. This means entries will exist
        # for at *LEAST* 30 mins, and at *MOST* 60 mins.
        self.cleaner = self.clock.looping_call(self._cleanup, CLEANUP_PERIOD_MS)

    def fetch_or_execute_request(self, request, fn, *args, **kwargs):
        """A helper function for fetch_or_execute which extracts
        a transaction key from the given request.

        See:
            fetch_or_execute
        """
        return self.fetch_or_execute(
            get_transaction_key(request), fn, *args, **kwargs
        )

    def fetch_or_execute(self, txn_key, fn, *args, **kwargs):
        """Fetches the response for this transaction, or executes the given function
        to produce a response for this transaction.

        Args:
            txn_key (str): A key to ensure idempotency should fetch_or_execute be
            called again at a later point in time.
            fn (function): A function which returns a tuple of
            (response_code, response_dict).
            *args: Arguments to pass to fn.
            **kwargs: Keyword arguments to pass to fn.
        Returns:
            Deferred which resolves to a tuple of (response_code, response_dict).
        """
        try:
            return self.transactions[txn_key][0].observe()
        except (KeyError, IndexError):
            pass  # execute the function instead.

        deferred = fn(*args, **kwargs)

        # We don't add an errback to the raw deferred, so we ask ObservableDeferred
        # to swallow the error. This is fine as the error will still be reported
        # to the observers.
        observable = ObservableDeferred(deferred, consumeErrors=True)
        self.transactions[txn_key] = (observable, self.clock.time_msec())
        return observable.observe()

    def _cleanup(self):
        now = self.clock.time_msec()
        for key in self.transactions.keys():
            ts = self.transactions[key][1]
            if now > (ts + CLEANUP_PERIOD_MS):  # after cleanup period
                del self.transactions[key]
