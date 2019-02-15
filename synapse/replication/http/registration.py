# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from twisted.internet import defer

from synapse.replication.http._base import ReplicationEndpoint

logger = logging.getLogger(__name__)


class RegistrationUserCacheInvalidationServlet(ReplicationEndpoint):
    """
    Invalidate the caches that a registration usually invalidates.

    Request format:

        POST /_synapse/replication/fed_query/:fed_cleanup_room/:txn_id

        {}
    """

    NAME = "reg_invalidate_user_caches"
    PATH_ARGS = ("user_id",)

    def __init__(self, hs):
        super(RegistrationUserCacheInvalidationServlet, self).__init__(hs)
        self.store = hs.get_datastore()

    @staticmethod
    def _serialize_payload(user_id, args):
        """
        Args:
            user_id (str)
        """
        return {}

    @defer.inlineCallbacks
    def _handle_request(self, request, user_id):

        def invalidate(txn):
            self.store._invalidate_cache_and_stream(
                txn, self.store.get_user_by_id, (user_id,)
            )
            txn.call_after(self.store.is_guest.invalidate, (user_id,))

        yield self.store.runInteraction("user_invalidate_caches", invalidate)
        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    RegistrationUserCacheInvalidationServlet(hs).register(http_server)
