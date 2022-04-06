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

import select
import time
from typing import Any, Iterable, List, Tuple

from prometheus_client import Histogram, Metric
from prometheus_client.core import REGISTRY, GaugeMetricFamily

from twisted.internet import reactor

from synapse.metrics._types import Collector

#
# Twisted reactor metrics
#

tick_time = Histogram(
    "python_twisted_reactor_tick_time",
    "Tick time of the Twisted reactor (sec)",
    buckets=[0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
)


class EpollWrapper:
    """a wrapper for an epoll object which records the time between polls"""

    def __init__(self, poller: "select.epoll"):  # type: ignore[name-defined]
        self.last_polled = time.time()
        self._poller = poller

    def poll(self, *args, **kwargs) -> List[Tuple[int, int]]:  # type: ignore[no-untyped-def]
        # record the time since poll() was last called. This gives a good proxy for
        # how long it takes to run everything in the reactor - ie, how long anything
        # waiting for the next tick will have to wait.
        tick_time.observe(time.time() - self.last_polled)

        ret = self._poller.poll(*args, **kwargs)

        self.last_polled = time.time()
        return ret

    def __getattr__(self, item: str) -> Any:
        return getattr(self._poller, item)


class ReactorLastSeenMetric(Collector):
    def __init__(self, epoll_wrapper: EpollWrapper):
        self._epoll_wrapper = epoll_wrapper

    def collect(self) -> Iterable[Metric]:
        cm = GaugeMetricFamily(
            "python_twisted_reactor_last_seen",
            "Seconds since the Twisted reactor was last seen",
        )
        cm.add_metric([], time.time() - self._epoll_wrapper.last_polled)
        yield cm


try:
    # if the reactor has a `_poller` attribute, which is an `epoll` object
    # (ie, it's an EPollReactor), we wrap the `epoll` with a thing that will
    # measure the time between ticks
    from select import epoll  # type: ignore[attr-defined]

    poller = reactor._poller  # type: ignore[attr-defined]
except (AttributeError, ImportError):
    pass
else:
    if isinstance(poller, epoll):
        poller = EpollWrapper(poller)
        reactor._poller = poller  # type: ignore[attr-defined]
        REGISTRY.register(ReactorLastSeenMetric(poller))
