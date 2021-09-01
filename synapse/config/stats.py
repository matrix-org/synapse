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

from ._base import Config

ROOM_STATS_DISABLED_WARN = """\
WARNING: room/user statistics have been disabled via the stats.enabled
configuration setting. This means that certain features (such as the room
directory) will not operate correctly. Future versions of Synapse may ignore
this setting.

To fix this warning, remove the stats.enabled setting from your configuration
file.
--------------------------------------------------------------------------------"""

logger = logging.getLogger(__name__)


class StatsConfig(Config):
    """Stats Configuration
    Configuration for the behaviour of synapse's stats engine
    """

    section = "stats"

    def read_config(self, config, **kwargs):
        self.stats_enabled = True
        self.stats_bucket_size = 86400 * 1000
        stats_config = config.get("stats", None)
        if stats_config:
            self.stats_enabled = stats_config.get("enabled", self.stats_enabled)
            self.stats_bucket_size = self.parse_duration(
                stats_config.get("bucket_size", "1d")
            )
        if not self.stats_enabled:
            logger.warning(ROOM_STATS_DISABLED_WARN)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """
        # Settings for local room and user statistics collection. See
        # https://matrix-org.github.io/synapse/latest/room_and_user_statistics.html.
        #
        stats:
          # Uncomment the following to disable room and user statistics. Note that doing
          # so may cause certain features (such as the room directory) not to work
          # correctly.
          #
          #enabled: false

          # The size of each timeslice in the room_stats_historical and
          # user_stats_historical tables, as a time period. Defaults to "1d".
          #
          #bucket_size: 1h
        """
