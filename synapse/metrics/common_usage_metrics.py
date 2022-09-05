# Copyright 2022 The Matrix.org Foundation C.I.C
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
from typing import TYPE_CHECKING

import attr

from synapse.metrics.background_process_metrics import run_as_background_process

if TYPE_CHECKING:
    from synapse.server import HomeServer

from prometheus_client import Gauge

# Gauge to expose daily active users metrics
current_dau_gauge = Gauge(
    "synapse_admin_daily_active_users",
    "Current daily active users count",
)


@attr.s(auto_attribs=True)
class CommonUsageMetrics:
    """Usage metrics shared between the phone home stats and the prometheus exporter."""

    daily_active_users: int


class CommonUsageMetricsManager:
    """Collects common usage metrics."""

    def __init__(self, hs: "HomeServer") -> None:
        self._store = hs.get_datastores().main
        self._clock = hs.get_clock()

    async def get_metrics(self) -> CommonUsageMetrics:
        """Get the CommonUsageMetrics object. If no collection has happened yet, do it
        before returning the metrics.

        Returns:
            The CommonUsageMetrics object to read common metrics from.
        """
        return await self._collect()

    async def setup(self) -> None:
        """Keep the gauges for common usage metrics up to date."""
        await self._update_gauges()
        self._clock.looping_call(
            run_as_background_process,
            5 * 60 * 1000,
            desc="common_usage_metrics_update_gauges",
            func=self._update_gauges,
        )

    async def _collect(self) -> CommonUsageMetrics:
        """Collect the common metrics and either create the CommonUsageMetrics object to
        use if it doesn't exist yet, or update it.
        """
        dau_count = await self._store.count_daily_users()

        return CommonUsageMetrics(
            daily_active_users=dau_count,
        )

    async def _update_gauges(self) -> None:
        """Update the Prometheus gauges."""
        metrics = await self._collect()

        current_dau_gauge.set(float(metrics.daily_active_users))
