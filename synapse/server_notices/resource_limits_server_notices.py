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

from synapse.api.errors import AuthError, SynapseError

logger = logging.getLogger(__name__)


class ResourceLimitsServerNotices(object):
    """
    """
    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer):
        """
        self._server_notices_manager = hs.get_server_notices_manager()
        self._store = hs.get_datastore()
        self.auth = hs.get_auth()
        self._server_notice_content = hs.config.user_consent_server_notice_content
        self._limit_usage_by_mau = hs.config.limit_usage_by_mau
        self._hs_disabled = hs.config.hs_disabled

        self._notified_of_blocking = set()
        self._resouce_limited = False
        # Config checks?

    @defer.inlineCallbacks
    def maybe_send_server_notice_to_user(self, user_id):
        """Check if we need to send a notice to this user, and does so if so

        Args:
            user_id (str): user to check

        Returns:
            Deferred
        """
        if self._hs_disabled is True:
            return

        if self._limit_usage_by_mau is True:
            timestamp = yield self._store.user_last_seen_monthly_active(user_id)
            if timestamp is None:
                # This user will be blocked from receiving the notice anyway.
                # In practice, not sure we can ever get here
                return
            try:
                yield self.auth.check_auth_blocking()
                self._resouce_limited = False
                # Need to start removing notices
                if user_id in self._notified_of_blocking:
                    # Send message to remove warning - needs updating
                    content = "remove warning"
                    self._send_server_notice(user_id, content)
                    self._notified_of_blocking.remove(user_id)

            except AuthError:
                # Need to start notifying of blocking

                self._resouce_limited = True
                if user_id not in self._notified_of_blocking:
                    # Send message to add warning - needs updating
                    content = "add warning"
                    self._send_server_notice(user_id, content)
                    self._notified_of_blocking.add(user_id)

    @defer.inlineCallbacks
    def _send_server_notice(self, user_id, content):
        """Sends Server notice

        Args:
            user_id(str): The user to send to
            content(str): The content of the message

        Returns:
            Deferred[]
        """
        try:
            yield self._server_notices_manager.send_notice(
                user_id, content,
            )
        except SynapseError as e:
            logger.error("Error sending server notice about resource limits: %s", e)
