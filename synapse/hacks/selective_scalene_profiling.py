# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import os
import time
from typing import Any, Callable, Dict, Optional

from scalene import scalene_profiler


class ProfilingDecider:
    INSTANCES: Dict[str, "ProfilingDecider"] = {}

    def __init__(self, name: str, cond: Callable[[], bool]) -> None:
        ProfilingDecider.INSTANCES[name] = self

        # Default to being armed if SCALENE is available as an env var.
        self.armed = b"SCALENE" in os.environb

        self._cond = cond

    def decide(self) -> bool:
        if not self.armed:
            return False

        if not self._cond():
            return False

        self.armed = False

        return True


class CpuUtimeTracker:
    def __init__(self) -> None:
        self._update_times(time.time())

    def _update_times(self, now_wall: float) -> None:
        utime, _, _, _, elapsed = os.times()
        self._last_utime = utime
        self._last_elapsed = elapsed
        self._last_wall = now_wall

        self.min_elapse = 0.5
        self.max_elapse = 120.0

    def update_return_utime(self) -> Optional[float]:
        """
        Returns CPU usage over this period, provided at least `min_elapse` have
        elapsed.
        """
        wall = time.time()
        elapsed = wall - self._last_wall
        if elapsed < self.min_elapse:
            return None

        last_utime = self._last_utime
        last_elapsed = self._last_elapsed

        self._update_times(wall)

        if elapsed > self.max_elapse:
            # the average will be a bit skewy if so much time has elapsed. Ignore.
            return None

        usage = (self._last_utime - last_utime) / (self._last_elapsed - last_elapsed)
        return usage


class SelectiveProfiling:
    def __init__(self, decider: ProfilingDecider, enable: bool = False):
        self._decider = decider
        self._enable = enable

    def __enter__(self) -> None:
        if not self._enable:
            return
        if not self._decider.decide():
            self._enable = False
            return
        scalene_profiler.start()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if not self._enable:
            scalene_profiler.stop()
