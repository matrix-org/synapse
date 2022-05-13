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
import enum
from typing import Awaitable, Callable, Generic, Optional, TypeVar, Union

from twisted.internet.defer import Deferred
from twisted.python.failure import Failure

from synapse.logging.context import make_deferred_yieldable, run_in_background

TV = TypeVar("TV")


class _Sentinel(enum.Enum):
    sentinel = object()


class CachedCall(Generic[TV]):
    """A wrapper for asynchronous calls whose results should be shared

    This is useful for wrapping asynchronous functions, where there might be multiple
    callers, but we only want to call the underlying function once (and have the result
    returned to all callers).

    Similar results can be achieved via a lock of some form, but that typically requires
    more boilerplate (and ends up being less efficient).

    Correctly handles Synapse logcontexts (logs and resource usage for the underlying
    function are logged against the logcontext which is active when get() is first
    called).

    Example usage:

        _cached_val = CachedCall(_load_prop)

        async def handle_request() -> X:
            # We can call this multiple times, but it will result in a single call to
            # _load_prop().
            return await _cached_val.get()

        async def _load_prop() -> X:
            await difficult_operation()


    The implementation is deliberately single-shot (ie, once the call is initiated,
    there is no way to ask for it to be run). This keeps the implementation and
    semantics simple. If you want to make a new call, simply replace the whole
    CachedCall object.
    """

    __slots__ = ["_callable", "_deferred", "_result"]

    def __init__(self, f: Callable[[], Awaitable[TV]]):
        """
        Args:
            f: The underlying function. Only one call to this function will be alive
                at once (per instance of CachedCall)
        """
        self._callable: Optional[Callable[[], Awaitable[TV]]] = f
        self._deferred: Optional[Deferred] = None
        self._result: Union[_Sentinel, TV, Failure] = _Sentinel.sentinel

    async def get(self) -> TV:
        """Kick off the call if necessary, and return the result"""

        # Fire off the callable now if this is our first time
        if not self._deferred:
            assert self._callable is not None
            self._deferred = run_in_background(self._callable)

            # we will never need the callable again, so make sure it can be GCed
            self._callable = None

            # once the deferred completes, store the result. We cannot simply leave the
            # result in the deferred, since `awaiting` a deferred destroys its result.
            # (Also, if it's a Failure, GCing the deferred would log a critical error
            # about unhandled Failures)
            def got_result(r: Union[TV, Failure]) -> None:
                self._result = r

            self._deferred.addBoth(got_result)

        # TODO: consider cancellation semantics. Currently, if the call to get()
        #    is cancelled, the underlying call will continue (and any future calls
        #    will get the result/exception), which I think is *probably* ok, modulo
        #    the fact the underlying call may be logged to a cancelled logcontext,
        #    and any eventual exception may not be reported.

        # we can now await the deferred, and once it completes, return the result.
        if isinstance(self._result, _Sentinel):
            await make_deferred_yieldable(self._deferred)
            assert not isinstance(self._result, _Sentinel)

        if isinstance(self._result, Failure):
            self._result.raiseException()
            raise AssertionError("unexpected return from Failure.raiseException")

        return self._result


class RetryOnExceptionCachedCall(Generic[TV]):
    """A wrapper around CachedCall which will retry the call if an exception is thrown

    This is used in much the same way as CachedCall, but adds some extra functionality
    so that if the underlying function throws an exception, then the next call to get()
    will initiate another call to the underlying function. (Any calls to get() which
    are already pending will raise the exception.)
    """

    slots = ["_cachedcall"]

    def __init__(self, f: Callable[[], Awaitable[TV]]):
        async def _wrapper() -> TV:
            try:
                return await f()
            except Exception:
                # the call raised an exception: replace the underlying CachedCall to
                # trigger another call next time get() is called
                self._cachedcall = CachedCall(_wrapper)
                raise

        self._cachedcall = CachedCall(_wrapper)

    async def get(self) -> TV:
        return await self._cachedcall.get()
