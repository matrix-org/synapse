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
from twisted.internet import defer


class WorkerServerNoticesSender(object):
    """Stub impl of ServerNoticesSender which does nothing"""

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """

    def on_user_syncing(self, user_id):
        """Called when the user performs a sync operation.

        Args:
            user_id (str): mxid of user who synced

        Returns:
            Deferred
        """
        return defer.succeed(None)

    def on_user_ip(self, user_id):
        """Called on the master when a worker process saw a client request.

        Args:
            user_id (str): mxid

        Returns:
            Deferred
        """
        raise AssertionError("on_user_ip unexpectedly called on worker")
