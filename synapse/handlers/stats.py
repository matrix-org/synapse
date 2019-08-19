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

from synapse.handlers.state_deltas import StateDeltasHandler

logger = logging.getLogger(__name__)


class StatsHandler(StateDeltasHandler):
    """Handles keeping the *_stats tables updated with a simple time-series of
    information about the users, rooms and media on the server, such that admins
    have some idea of who is consuming their resources.

    Heavily derived from UserDirectoryHandler
    """

    def __init__(self, hs):
        super(StatsHandler, self).__init__(hs)
        self.hs = hs
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.stats_bucket_size = hs.config.stats_bucket_size

        # The current position in the current_state_delta stream
        self.pos = None

        if hs.config.stats_enabled:
            self.notifier.add_replication_callback(self.notify_new_event)

            # We kick this off so that we don't have to wait for a change before
            # we start populating stats
            self.clock.call_later(0, self.notify_new_event)

    def notify_new_event(self):
        """Called when there may be more deltas to process
        """
        pass
