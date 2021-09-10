# Copyright 2014 - 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Optional

from synapse.api.ratelimiting import Ratelimiter

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class BaseHandler:
    """
    Common base class for the event handlers.

    Deprecated: new code should not use this. Instead, Handler classes should define the
    fields they actually need. The utility methods should either be factored out to
    standalone helper functions, or to different Handler classes.
    """

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.state_handler = hs.get_state_handler()
        self.distributor = hs.get_distributor()
        self.clock = hs.get_clock()
        self.hs = hs

        # The rate_hz and burst_count are overridden on a per-user basis
        self.request_ratelimiter = Ratelimiter(
            store=self.store, clock=self.clock, rate_hz=0, burst_count=0
        )
        self._rc_message = self.hs.config.ratelimiting.rc_message

        # Check whether ratelimiting room admin message redaction is enabled
        # by the presence of rate limits in the config
        if self.hs.config.ratelimiting.rc_admin_redaction:
            self.admin_redaction_ratelimiter: Optional[Ratelimiter] = Ratelimiter(
                store=self.store,
                clock=self.clock,
                rate_hz=self.hs.config.ratelimiting.rc_admin_redaction.per_second,
                burst_count=self.hs.config.ratelimiting.rc_admin_redaction.burst_count,
            )
        else:
            self.admin_redaction_ratelimiter = None

        self.server_name = hs.hostname

        self.event_builder_factory = hs.get_event_builder_factory()

    async def ratelimit(self, requester, update=True, is_admin_redaction=False):
        """Ratelimits requests.

        Args:
            requester (Requester)
            update (bool): Whether to record that a request is being processed.
                Set to False when doing multiple checks for one request (e.g.
                to check up front if we would reject the request), and set to
                True for the last call for a given request.
            is_admin_redaction (bool): Whether this is a room admin/moderator
                redacting an event. If so then we may apply different
                ratelimits depending on config.

        Raises:
            LimitExceededError if the request should be ratelimited
        """
        user_id = requester.user.to_string()

        # The AS user itself is never rate limited.
        app_service = self.store.get_app_service_by_user_id(user_id)
        if app_service is not None:
            return  # do not ratelimit app service senders

        messages_per_second = self._rc_message.per_second
        burst_count = self._rc_message.burst_count

        # Check if there is a per user override in the DB.
        override = await self.store.get_ratelimit_for_user(user_id)
        if override:
            # If overridden with a null Hz then ratelimiting has been entirely
            # disabled for the user
            if not override.messages_per_second:
                return

            messages_per_second = override.messages_per_second
            burst_count = override.burst_count

        if is_admin_redaction and self.admin_redaction_ratelimiter:
            # If we have separate config for admin redactions, use a separate
            # ratelimiter as to not have user_ids clash
            await self.admin_redaction_ratelimiter.ratelimit(requester, update=update)
        else:
            # Override rate and burst count per-user
            await self.request_ratelimiter.ratelimit(
                requester,
                rate_hz=messages_per_second,
                burst_count=burst_count,
                update=update,
            )
