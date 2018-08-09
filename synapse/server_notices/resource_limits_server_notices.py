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

from six import iteritems, string_types

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.api.urls import ConsentURIBuilder
from synapse.config import ConfigError
from synapse.types import get_localpart_from_id

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
        self._api = hs.get_api()
        self._server_notice_content = hs.config.user_consent_server_notice_content
        self._limit_usage_by_mau = config.limit_usage_by_mau = False
        self._hs_disabled.config.hs_disabled = False

        self._notified = set()
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
        if self._limit_usage_by_mau is False and self._hs_disabled is False:
            # not enabled
            return

        timestamp = yield self.store.user_last_seen_monthly_active(user_id)
        if timestamp is None:
            # This user will be blocked from receiving the notice anyway
            return
        try:
            yield self.api.check_auth_blocking()
            if self._resouce_limited:
                # Need to start removing notices
                pass
        except AuthError as e:
            # Need to start notifying of blocking
            if not self._resouce_limited:
                pass

            # need to send a message.
            try:
                yield self._server_notices_manager.send_notice(
                    user_id, content,
                )

            except SynapseError as e:
                logger.error("Error sending server notice about resource limits: %s", e)
