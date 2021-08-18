# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from synapse.config._base import Config, ConfigError
from synapse.python_dependencies import DependencyException, check_requirements


class StateCompressorConfig(Config):
    section = "statecompressor"

    def read_config(self, config, **kwargs):
        compressor_config = config.get("state_compressor") or {}
        self.compressor_enabled = compressor_config.get("enabled") or False

        if not self.compressor_enabled:
            return

        try:
            check_requirements("auto_compressor")
        except DependencyException as e:
            raise ConfigError(e.message)

        self.compressor_chunk_size = compressor_config.get("chunk_size") or 500
        self.compressor_number_of_rooms = compressor_config.get("number_of_rooms") or 5
        self.compressor_default_levels = (
            compressor_config.get("default_levels") or "100,50,25"
        )
        self.time_between_compressor_runs = self.parse_duration(
            compressor_config.get("time_between_runs") or "1d"
        )

    def generate_config_section(self, **kwargs):
        return """\
        # The state compressor is an experimental tool which attempts to
        # reduce the number of rows in the state_groups_state table
        # of postgres databases.
        #
        # For more information please see
        # https://matrix-org.github.io/synapse/latest/state_compressor.html
        #
        state_compressor:
        #  enabled: true
        #  # The (rough) number of state groups to load at one time
        #  chunk_size: 500
        #  # The number of rooms to compress on each run
        #  number_of_rooms: 5
        #  # The default level sizes for the compressor to use
        #  default_levels: 100,50,25
        #  # How frequently to run the state compressor
        #  time_between_runs: 1d
        """
