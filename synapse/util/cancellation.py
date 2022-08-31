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
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def cancellable(function: F) -> F:
    """Marks a function as cancellable.

    Servlet methods with this decorator will be cancelled if the client disconnects before we
    finish processing the request.

    Although this annotation is particularly useful for servlet methods, it's also
    useful for intermediate functions, where it documents the fact that the function has
    been audited for cancellation safety and needs to preserve that.
    This then simplifies auditing new functions that call those same intermediate
    functions.

    During cancellation, `Deferred.cancel()` will be invoked on the `Deferred` wrapping
    the method. The `cancel()` call will propagate down to the `Deferred` that is
    currently being waited on. That `Deferred` will raise a `CancelledError`, which will
    propagate up, as per normal exception handling.

    Before applying this decorator to a new function, you MUST recursively check
    that all `await`s in the function are on `async` functions or `Deferred`s that
    handle cancellation cleanly, otherwise a variety of bugs may occur, ranging from
    premature logging context closure, to stuck requests, to database corruption.

    See the documentation page on Cancellation for more information.

    Usage:
        class SomeServlet(RestServlet):
            @cancellable
            async def on_GET(self, request: SynapseRequest) -> ...:
                ...
    """

    function.cancellable = True  # type: ignore[attr-defined]
    return function


def is_function_cancellable(function: Callable[..., Any]) -> bool:
    """Checks whether a servlet method has the `@cancellable` flag."""
    return getattr(function, "cancellable", False)
