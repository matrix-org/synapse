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

from synapse.metrics.background_process_metrics import run_as_background_process

if TYPE_CHECKING:
    from synapse.server import HomeServer

from prometheus_client import Gauge

# Gauge to expose daily active users metrics
current_dau_gauge = Gauge(
    "synapse_admin_daily_active_users",
    "Current daily active users count",
)


class SharedUsageMetrics:
    """Usage metrics shared between the phone home stats and the prometheus exporter."""

    def __init__(self, hs: "HomeServer") -> None:
        self._store = hs.get_datastores().main
        self._clock = hs.get_clock()

        self.daily_active_users = -1

    async def setup(self) -> None:
        """Reads the current values for the shared usage metrics and starts a looping
        call to keep them updated.
        """
        await self.update()
        self._clock.looping_call(
            run_as_background_process,
            5 * 60 * 1000,
            desc="update_shared_usage_metrics",
            func=self.update,
        )

    async def update(self) -> None:
        """Updates the shared usage metrics."""
        await self.update_daily_active_users()

    async def update_daily_active_users(self) -> None:
        """Updates the daily active users count."""
        dau_count = await self._store.count_daily_users()
        current_dau_gauge.set(float(dau_count))
        self.daily_active_users = dau_count
