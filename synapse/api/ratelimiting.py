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

import collections

from synapse.api.errors import LimitExceededError


class Ratelimiter(object):
    """
    Ratelimit message sending by user.
    """

    def __init__(self):
        self.message_counts = collections.OrderedDict()

    def can_do_action(self, key, time_now_s, rate_hz, burst_count, update=True):
        """Can the entity (e.g. user or IP address) perform the action?
        Args:
            key: The key we should use when rate limiting. Can be a user ID
                (when sending events), an IP address, etc.
            time_now_s: The time now.
            rate_hz: The long term number of messages a user can send in a
                second.
            burst_count: How many messages the user can send before being
                limited.
            update (bool): Whether to update the message rates or not. This is
                useful to check if a message would be allowed to be sent before
                its ready to be actually sent.
        Returns:
            A pair of a bool indicating if they can send a message now and a
                time in seconds of when they can next send a message.
        """
        self.prune_message_counts(time_now_s)
        message_count, time_start, _ignored = self.message_counts.get(
            key, (0., time_now_s, None),
        )
        time_delta = time_now_s - time_start
        sent_count = message_count - time_delta * rate_hz
        if sent_count < 0:
            allowed = True
            time_start = time_now_s
            message_count = 1.
        elif sent_count > burst_count - 1.:
            allowed = False
        else:
            allowed = True
            message_count += 1

        if update:
            self.message_counts[key] = (
                message_count, time_start, rate_hz
            )

        if rate_hz > 0:
            time_allowed = (
                time_start + (message_count - burst_count + 1) / rate_hz
            )
            if time_allowed < time_now_s:
                time_allowed = time_now_s
        else:
            time_allowed = -1

        return allowed, time_allowed

    def prune_message_counts(self, time_now_s):
        for key in list(self.message_counts.keys()):
            message_count, time_start, rate_hz = (
                self.message_counts[key]
            )
            time_delta = time_now_s - time_start
            if message_count - time_delta * rate_hz > 0:
                break
            else:
                del self.message_counts[key]

    def ratelimit(self, key, time_now_s, rate_hz, burst_count, update=True):
        allowed, time_allowed = self.can_do_action(
            key, time_now_s, rate_hz, burst_count, update
        )

        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now_s)),
            )
