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

from collections import OrderedDict
from typing import Any, Tuple

from synapse.api.errors import LimitExceededError


class Ratelimiter(object):
    """
    Ratelimit actions marked by arbitrary keys.

    Args:
        rate_hz: The long term number of actions that can be performed in a
            second.
        burst_count: How many actions that can be performed before being
            limited.
    """

    def __init__(self, rate_hz: float, burst_count: int):
        # A ordered dictionary keeping track of actions, when they were last
        # performed and how often. Each entry is a mapping from a key of arbitrary type
        # to a tuple representing:
        #   * How many times an action has occurred since a point in time
        #   * That point in time
        self.actions = OrderedDict()  # type: OrderedDict[Any, Tuple[float, int]]
        self.rate_hz = rate_hz
        self.burst_count = burst_count

    def can_do_action(
        self, key: Any, time_now_s: int, update: bool = True,
    ) -> Tuple[bool, float]:
        """Can the entity (e.g. user or IP address) perform the action?

        Args:
            key: The key we should use when rate limiting. Can be a user ID
                (when sending events), an IP address, etc.
            time_now_s: The time now
            update: Whether to count this check as performing the action
        Returns:
            A tuple containing:
                * A bool indicating if they can perform the action now
                * The time in seconds of when it can next be performed.
                  -1 if a rate_hz has not been defined for this Ratelimiter
        """
        # Remove any expired entries
        self._prune_message_counts(time_now_s)

        # Check if there is an existing count entry for this key
        action_count, time_start, = self.actions.get(key, (0.0, time_now_s))

        # Check whether performing another action is allowed
        time_delta = time_now_s - time_start
        performed_count = action_count - time_delta * self.rate_hz
        if performed_count < 0:
            # Allow, reset back to count 1
            allowed = True
            time_start = time_now_s
            action_count = 1.0
        elif performed_count > self.burst_count - 1.0:
            # Deny, we have exceeded our burst count
            allowed = False
        else:
            # We haven't reached our limit yet
            allowed = True
            action_count += 1.0

        if update:
            self.actions[key] = (action_count, time_start)

        # Figure out the time when an action can be performed again
        if self.rate_hz > 0:
            time_allowed = (
                time_start + (action_count - self.burst_count + 1) / self.rate_hz
            )

            # Don't give back a time in the past
            if time_allowed < time_now_s:
                time_allowed = time_now_s
        else:
            # This does not apply
            time_allowed = -1

        return allowed, time_allowed

    def _prune_message_counts(self, time_now_s: int):
        """Remove message count entries that are older than

        Args:
            time_now_s: The current time
        """
        # We create a copy of the key list here as the dictionary is modified during
        # the loop
        for key in list(self.actions.keys()):
            action_count, time_start = self.actions[key]

            time_delta = time_now_s - time_start
            if action_count - time_delta * self.rate_hz > 0:
                # XXX: Should this be a continue?
                break
            else:
                del self.actions[key]

    def ratelimit(
        self, key: Any, time_now_s: int, update: bool = True,
    ):
        """Checks if an action can be performed. If not, raises a LimitExceededError

        Args:
            key: An arbitrary key used to classify an action
            time_now_s: The current time
            update: Whether to count this check as performing the action

        Raises:
            LimitExceededError: If an action could not be performed, along with the time in
                milliseconds until the action can be performed again
        """
        allowed, time_allowed = self.can_do_action(key, time_now_s, update)

        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now_s))
            )
