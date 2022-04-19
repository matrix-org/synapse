# Copyright 2022 Matrix.org Foundation C.I.C.
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
from typing import Any

from synapse.types import JsonDict

from ._base import Config


class BackgroundUpdateConfig(Config):
    section = "background_updates"

    def generate_config_section(self, **kwargs: Any) -> str:
        return """\
        ## Background Updates ##

        # Background updates are database updates that are run in the background in batches.
        # The duration, minimum batch size, default batch size, whether to sleep between batches and if so, how long to
        # sleep can all be configured. This is helpful to speed up or slow down the updates.
        #
        background_updates:
            # How long in milliseconds to run a batch of background updates for. Defaults to 100. Uncomment and set
            # a time to change the default.
            #
            #background_update_duration_ms: 500

            # Whether to sleep between updates. Defaults to True. Uncomment to change the default.
            #
            #sleep_enabled: false

            # If sleeping between updates, how long in milliseconds to sleep for. Defaults to 1000. Uncomment
            # and set a duration to change the default.
            #
            #sleep_duration_ms: 300

            # Minimum size a batch of background updates can be. Must be greater than 0. Defaults to 1. Uncomment and
            # set a size to change the default.
            #
            #min_batch_size: 10

            # The batch size to use for the first iteration of a new background update. The default is 100.
            # Uncomment and set a size to change the default.
            #
            #default_batch_size: 50
        """

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        bg_update_config = config.get("background_updates") or {}

        self.update_duration_ms = bg_update_config.get(
            "background_update_duration_ms", 100
        )

        self.sleep_enabled = bg_update_config.get("sleep_enabled", True)

        self.sleep_duration_ms = bg_update_config.get("sleep_duration_ms", 1000)

        self.min_batch_size = bg_update_config.get("min_batch_size", 1)

        self.default_batch_size = bg_update_config.get("default_batch_size", 100)
