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

import logging
import time
from selectors import SelectSelector, _PollLikeSelector  # type: ignore[attr-defined]
from typing import Any, Callable, Iterable

from prometheus_client import Histogram, Metric
from prometheus_client.core import REGISTRY, GaugeMetricFamily

from twisted.internet import reactor
from twisted.internet.asyncioreactor import AsyncioSelectorReactor
from twisted.internet.selectreactor import SelectReactor

from synapse.metrics._types import Collector

try:
    from selectors import KqueueSelector
except ImportError:

    class KqueueSelector:  # type: ignore[no-redef]
        pass


try:
    from twisted.internet.epollreactor import EPollReactor
except ImportError:

    class EPollReactor:  # type: ignore[no-redef]
        pass


try:
    from twisted.internet.pollreactor import PollReactor
except ImportError:

    class PollReactor:  # type: ignore[no-redef]
        pass


logger = logging.getLogger(__name__)

#
# Twisted reactor metrics
#

tick_time = Histogram(
    "python_twisted_reactor_tick_time",
    "Tick time of the Twisted reactor (sec)",
    buckets=[0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
)


class CallWrapper:
    """a wrapper for a callable which records the time between calls"""

    def __init__(self, wrapped: Callable[..., Any]):
        self.last_polled = time.time()
        self._wrapped = wrapped

    def __call__(self, *args, **kwargs) -> Any:  # type: ignore[no-untyped-def]
        # record the time since this was last called. This gives a good proxy for
        # how long it takes to run everything in the reactor - ie, how long anything
        # waiting for the next tick will have to wait.
        tick_time.observe(time.time() - self.last_polled)

        ret = self._wrapped(*args, **kwargs)

        self.last_polled = time.time()
        return ret


class ObjWrapper:
    """a wrapper for an callable which records the time between calls"""

    def __init__(self, wrapped: Any, method: str):
        self._wrapped = wrapped
        self._method = method
        self._wrapped_method = CallWrapper(getattr(wrapped, method))

    def __getattr__(self, item: str) -> Any:
        if item == self._method:
            return self._wrapped_method

        return getattr(self._wrapped, item)


class ReactorLastSeenMetric(Collector):
    def __init__(self, call_wrapper: CallWrapper):
        self._call_wrapper = call_wrapper

    def collect(self) -> Iterable[Metric]:
        cm = GaugeMetricFamily(
            "python_twisted_reactor_last_seen",
            "Seconds since the Twisted reactor was last seen",
        )
        cm.add_metric([], time.time() - self._call_wrapper.last_polled)
        yield cm


# Twisted has already select a reasonable reactor for us, so assumptions can be
# made about the shape.
wrapper = None
if isinstance(reactor, (PollReactor, EPollReactor)):
    wrapper = reactor._poller.poll = CallWrapper(reactor._poller.poll)

elif isinstance(reactor, SelectReactor):
    from twisted.internet import selectreactor

    wrapper = selectreactor._select = CallWrapper(selectreactor._select)

elif isinstance(reactor, AsyncioSelectorReactor):
    # For asyncio we need to go deeper.
    asyncio_loop = reactor._asyncioEventloop  # A sub-class of BaseEventLoop,

    # If an unexpected asyncio loop implementation is used, these might fail.
    try:
        # A sub-class of BaseSelector.
        selector = asyncio_loop._selector  # type: ignore[attr-defined]

        if isinstance(selector, SelectSelector):
            wrapper = selector._select = CallWrapper(selector._select)  # type: ignore[attr-defined]

        # poll, epoll, and /dev/poll.
        elif isinstance(selector, _PollLikeSelector):
            selector._selector = ObjWrapper(selector._selector, "poll")  # type: ignore[attr-defined]
            wrapper = selector._selector._wrapped_method  # type: ignore[attr-defined]

        elif isinstance(selector, KqueueSelector):
            selector._selector = ObjWrapper(selector._selector, "control")  # type: ignore[attr-defined]
            wrapper = selector._selector._wrapped_method  # type: ignore[attr-defined]

        # XXX Will not work on (Windows-only) ProactorEventLoop.
    except AttributeError:
        logger.warn("Unexpected asyncio loop: %r", asyncio_loop)

if wrapper:
    REGISTRY.register(ReactorLastSeenMetric(wrapper))
