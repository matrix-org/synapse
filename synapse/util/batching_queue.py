# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import (
    Awaitable,
    Callable,
    Dict,
    Generic,
    Hashable,
    List,
    Set,
    Tuple,
    TypeVar,
)

from prometheus_client import Gauge

from twisted.internet import defer

from synapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.util import Clock

logger = logging.getLogger(__name__)


V = TypeVar("V")
R = TypeVar("R")

number_queued = Gauge(
    "synapse_util_batching_queue_number_queued",
    "The number of items waiting in the queue across all keys",
    labelnames=("name",),
)

number_in_flight = Gauge(
    "synapse_util_batching_queue_number_pending",
    "The number of items across all keys either being processed or waiting in a queue",
    labelnames=("name",),
)

number_of_keys = Gauge(
    "synapse_util_batching_queue_number_of_keys",
    "The number of distinct keys that have items queued",
    labelnames=("name",),
)


class BatchingQueue(Generic[V, R]):
    """A queue that batches up work, calling the provided processing function
    with all pending work (for a given key).

    The provided processing function will only be called once at a time for each
    key. It will be called the next reactor tick after `add_to_queue` has been
    called, and will keep being called until the queue has been drained (for the
    given key).

    If the processing function raises an exception then the exception is proxied
    through to the callers waiting on that batch of work.

    Note that the return value of `add_to_queue` will be the return value of the
    processing function that processed the given item. This means that the
    returned value will likely include data for other items that were in the
    batch.

    Args:
        name: A name for the queue, used for logging contexts and metrics.
            This must be unique, otherwise the metrics will be wrong.
        clock: The clock to use to schedule work.
        process_batch_callback: The callback to to be run to process a batch of
            work.
    """

    def __init__(
        self,
        name: str,
        clock: Clock,
        process_batch_callback: Callable[[List[V]], Awaitable[R]],
    ):
        self._name = name
        self._clock = clock

        # The set of keys currently being processed.
        self._processing_keys: Set[Hashable] = set()

        # The currently pending batch of values by key, with a Deferred to call
        # with the result of the corresponding `_process_batch_callback` call.
        self._next_values: Dict[Hashable, List[Tuple[V, defer.Deferred]]] = {}

        # The function to call with batches of values.
        self._process_batch_callback = process_batch_callback

        number_queued.labels(self._name).set_function(
            lambda: sum(len(q) for q in self._next_values.values())
        )

        number_of_keys.labels(self._name).set_function(lambda: len(self._next_values))

        self._number_in_flight_metric: Gauge = number_in_flight.labels(self._name)

    async def add_to_queue(self, value: V, key: Hashable = ()) -> R:
        """Adds the value to the queue with the given key, returning the result
        of the processing function for the batch that included the given value.

        The optional `key` argument allows sharding the queue by some key. The
        queues will then be processed in parallel, i.e. the process batch
        function will be called in parallel with batched values from a single
        key.
        """

        # First we create a defer and add it and the value to the list of
        # pending items.
        d: defer.Deferred[R] = defer.Deferred()
        self._next_values.setdefault(key, []).append((value, d))

        # If we're not currently processing the key fire off a background
        # process to start processing.
        if key not in self._processing_keys:
            run_as_background_process(self._name, self._process_queue, key)

        with self._number_in_flight_metric.track_inprogress():
            return await make_deferred_yieldable(d)

    async def _process_queue(self, key: Hashable) -> None:
        """A background task to repeatedly pull things off the queue for the
        given key and call the `self._process_batch_callback` with the values.
        """

        if key in self._processing_keys:
            return

        try:
            self._processing_keys.add(key)

            while True:
                # We purposefully wait a reactor tick to allow us to batch
                # together requests that we're about to receive. A common
                # pattern is to call `add_to_queue` multiple times at once, and
                # deferring to the next reactor tick allows us to batch all of
                # those up.
                await self._clock.sleep(0)

                next_values = self._next_values.pop(key, [])
                if not next_values:
                    # We've exhausted the queue.
                    break

                try:
                    values = [value for value, _ in next_values]
                    results = await self._process_batch_callback(values)

                    with PreserveLoggingContext():
                        for _, deferred in next_values:
                            deferred.callback(results)

                except Exception as e:
                    with PreserveLoggingContext():
                        for _, deferred in next_values:
                            if deferred.called:
                                continue

                            deferred.errback(e)

        finally:
            self._processing_keys.discard(key)
