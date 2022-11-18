# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from typing import Any, Optional

import attr

from synapse.types import JsonDict
from synapse.util.check_dependencies import check_requirements

from ._base import Config, ConfigError


@attr.s
class MetricsFlags:
    known_servers: bool = attr.ib(
        default=False, validator=attr.validators.instance_of(bool)
    )

    @classmethod
    def all_off(cls) -> "MetricsFlags":
        """
        Instantiate the flags with all options set to off.
        """
        return cls(**{x.name: False for x in attr.fields(cls)})


class MetricsConfig(Config):
    section = "metrics"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.enable_metrics = config.get("enable_metrics", False)

        self.enable_legacy_metrics = config.get("enable_legacy_metrics", False)

        self.report_stats = config.get("report_stats", None)
        self.report_stats_endpoint = config.get(
            "report_stats_endpoint", "https://matrix.org/report-usage-stats/push"
        )
        self.metrics_port = config.get("metrics_port")
        self.metrics_bind_host = config.get("metrics_bind_host", "127.0.0.1")

        if self.enable_metrics:
            _metrics_config = config.get("metrics_flags") or {}
            self.metrics_flags = MetricsFlags(**_metrics_config)
        else:
            self.metrics_flags = MetricsFlags.all_off()

        self.sentry_enabled = "sentry" in config
        if self.sentry_enabled:
            check_requirements("sentry")

            self.sentry_dsn = config["sentry"].get("dsn")
            if not self.sentry_dsn:
                raise ConfigError(
                    "sentry.dsn field is required when sentry integration is enabled"
                )

    def generate_config_section(
        self, report_stats: Optional[bool] = None, **kwargs: Any
    ) -> str:
        if report_stats is not None:
            res = "report_stats: %s\n" % ("true" if report_stats else "false")
        else:
            res = "\n"
        return res
