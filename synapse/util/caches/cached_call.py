# -*- coding: utf-8 -*-
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

from typing import Awaitable, Callable, Generic, Optional, TypeVar

from twisted.internet.defer import Deferred

from synapse.logging.context import make_deferred_yieldable, run_in_background

TV = TypeVar("TV")


class CachedCall(Generic[TV]):
    """A wrapper for asynchronous calls whose results should be shared

    This is useful for wrapping asynchronous functions, where there might be multiple
    callers, but we only want to call the underlying function once (and have the result
    returned to all callers).

    Similar results can be achieved via a lock of some form, but that typically requires
    more boilerplate (and ends up being less efficient).

    Example usage:

        _cached_val = CachedCall(_load_prop)

        async def handle_request() -> X:
            # We can call this multiple times, but it will result in a single call to
            # _load_prop().
            return await _cached_val.get()

        async def _load_prop() -> X:
            await difficult_operation()

    """

    __slots__ = ["callable", "retry_on_exception", "_deferred"]

    def __init__(
        self, callable: Callable[[], Awaitable[TV]], retry_on_exception: bool = False
    ):
        """
        Args:
            callable: The underlying function. Only one call to this function will be alive
                at once (per instance of CachedCall)

            retry_on_exception: If set to True, then, if `callable` raises an Exception,
                the next call to `get()` will initiate a new call to `callable()`. (Any
                pending calls to `get()` will still all receive the same Exception.)

        """
        self.callable = callable
        self.retry_on_exception = retry_on_exception
        self._deferred = None  # type: Optional[Deferred]

    async def get(self) -> TV:
        """Kick off the call if necessary, and return the result"""

        # if we don't already have a fetcher, fire it off now
        fetch_deferred = self._deferred
        if not fetch_deferred:
            self._deferred = run_in_background(self.callable)

            # take a copy of the deferred before maybe clearing it again
            fetch_deferred = self._deferred

            if self.retry_on_exception:
                # if there is an exception, reset the deferred so that we try again
                # next time
                def eb(f):
                    self.clear()
                    return f

                fetch_deferred.addErrback(eb)

        # TODO: consider whether we want to set a maximum number of waiters:
        #    could be implemented by checking the number of `callbacks` on _deferred.

        # TODO: consider cancellation semantics. Currently, if the call to get()
        #    is cancelled, the underlying call will continue (and any future calls
        #    will get the result/exception), which I think is *probably* ok, modulo
        #    the fact the underlying call may be logged to a cancelled logcontext.

        # we can now await the deferred. This is made somewhat painful by the desire to
        # avoid disturbing the result of _deferred: we do so by
        # constructing a *new* Deferred, which we can then safely pass back to the
        # twisted coroutine wrapper.
        d = Deferred()

        def cb(r):
            d.callback(r)
            return r

        fetch_deferred.addBoth(cb)

        return await make_deferred_yieldable(d)

    def clear(self):
        """Clear any stored result

        This will cause the next call to get() to initiate a new call.
        """
        self._deferred = None
