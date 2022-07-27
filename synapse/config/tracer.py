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
        opentelemetry_config = config.get("opentelemetry")
        if opentelemetry_config is None:
            opentelemetry_config = {}

        self.opentelemetry_enabled = opentelemetry_config.get("enabled", False)

        # TODO: no more
        self.jaeger_exporter_config = opentelemetry_config.get(
            "jaeger_exporter_config",
            {},
        )

        self.force_tracing_for_users: Set[str] = set()

        if not self.opentelemetry_enabled:
            return

        check_requirements("opentelemetry")

        # The tracer is enabled so sanitize the config

        self.opentelemetry_whitelist: List[str] = opentelemetry_config.get(
            "homeserver_whitelist", []
        )
        if not isinstance(self.opentelemetry_whitelist, list):
            raise ConfigError("Tracer homeserver_whitelist config is malformed")

        force_tracing_for_users = opentelemetry_config.get(
            "force_tracing_for_users", []
        )
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
