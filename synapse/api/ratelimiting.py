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


class Ratelimiter(object):
    """
    Ratelimit message sending by user.
    """

    def __init__(self):
        self.message_counts = collections.OrderedDict()

    def send_message(self, user_id, time_now_s, msg_rate_hz, burst_count, update=True):
        """Can the user send a message?
        Args:
            user_id: The user sending a message.
            time_now_s: The time now.
            msg_rate_hz: The long term number of messages a user can send in a
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
            user_id, (0., time_now_s, None),
        )
        time_delta = time_now_s - time_start
        sent_count = message_count - time_delta * msg_rate_hz
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
            self.message_counts[user_id] = (
                message_count, time_start, msg_rate_hz
            )

        if msg_rate_hz > 0:
            time_allowed = (
                time_start + (message_count - burst_count + 1) / msg_rate_hz
            )
            if time_allowed < time_now_s:
                time_allowed = time_now_s
        else:
            time_allowed = -1

        return allowed, time_allowed

    def prune_message_counts(self, time_now_s):
        for user_id in self.message_counts.keys():
            message_count, time_start, msg_rate_hz = (
                self.message_counts[user_id]
            )
            time_delta = time_now_s - time_start
            if message_count - time_delta * msg_rate_hz > 0:
                break
            else:
                del self.message_counts[user_id]
