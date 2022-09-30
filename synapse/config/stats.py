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
from typing import Any

from synapse.types import JsonDict

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

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.stats_enabled = True
        stats_config = config.get("stats", None)
        if stats_config:
            self.stats_enabled = stats_config.get("enabled", self.stats_enabled)
        if not self.stats_enabled:
            logger.warning(ROOM_STATS_DISABLED_WARN)
