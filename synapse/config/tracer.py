# Copyright 2019 The Matrix.org Foundation C.I.C.d
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

from typing import Any, List, Set

from synapse.types import JsonDict
from synapse.util.check_dependencies import check_requirements

from ._base import Config, ConfigError


class TracerConfig(Config):
    section = "tracing"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        tracing_config = config.get("tracing")
        if tracing_config is None:
            tracing_config = {}

        self.tracing_enabled = tracing_config.get("enabled", False)

        self.jaeger_exporter_config = tracing_config.get(
            "jaeger_exporter_config",
            {},
        )

        self.force_tracing_for_users: Set[str] = set()

        if not self.tracing_enabled:
            return

        check_requirements("opentelemetry")

        # The tracer is enabled so sanitize the config

        # Default to always sample. Range: [0.0 - 1.0]
        self.sample_rate: float = float(tracing_config.get("sample_rate", 1))
        if self.sample_rate < 0.0 or self.sample_rate > 1.0:
            raise ConfigError("Tracing sample_rate must be in range [0.0, 1.0].")

        self.homeserver_whitelist: List[str] = tracing_config.get(
            "homeserver_whitelist", []
        )
        if not isinstance(self.homeserver_whitelist, list):
            raise ConfigError("Tracing homeserver_whitelist config is malformed")

        force_tracing_for_users = tracing_config.get("force_tracing_for_users", [])
        if not isinstance(force_tracing_for_users, list):
            raise ConfigError(
                "Expected a list", ("opentelemetry", "force_tracing_for_users")
            )
        for i, u in enumerate(force_tracing_for_users):
            if not isinstance(u, str):
                raise ConfigError(
                    "Expected a string",
                    ("opentelemetry", "force_tracing_for_users", f"index {i}"),
                )
            self.force_tracing_for_users.add(u)
