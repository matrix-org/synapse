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

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        bg_update_config = config.get("background_updates") or {}

        self.update_duration_ms = bg_update_config.get(
            "background_update_duration_ms", 100
        )

        self.sleep_enabled = bg_update_config.get("sleep_enabled", True)

        self.sleep_duration_ms = bg_update_config.get("sleep_duration_ms", 1000)

        self.min_batch_size = bg_update_config.get("min_batch_size", 1)

        self.default_batch_size = bg_update_config.get("default_batch_size", 100)
