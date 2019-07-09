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

from __future__ import division

import sys

from ._base import Config


class StatsConfig(Config):
    """Stats Configuration
    Configuration for the behaviour of synapse's stats engine
    """

    def read_config(self, config, **kwargs):
        self.stats_enabled = True
        self.stats_bucket_size = 86400
        self.stats_retention = sys.maxsize
        stats_config = config.get("stats", None)
        if stats_config:
            self.stats_enabled = stats_config.get("enabled", self.stats_enabled)
            self.stats_bucket_size = (
                self.parse_duration(stats_config.get("bucket_size", "1d")) / 1000
            )
            self.stats_retention = (
                self.parse_duration(
                    stats_config.get("retention", "%ds" % (sys.maxsize,))
                )
                / 1000
            )

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """
        # Local statistics collection. Used in populating the room directory.
        #
        # 'bucket_size' controls how large each statistics timeslice is. It can
        # be defined in a human readable short form -- e.g. "1d", "1y".
        #
        # 'retention' controls how long historical statistics will be kept for.
        # It can be defined in a human readable short form -- e.g. "1d", "1y".
        #
        #
        #stats:
        #   enabled: true
        #   bucket_size: 1d
        #   retention: 1y
        """
