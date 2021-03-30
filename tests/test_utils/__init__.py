# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C
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

"""
Utilities for running the unit tests
"""
import sys
import warnings
from asyncio import Future
from typing import Any, Awaitable, Callable, TypeVar

from unittest.mock import Mock

import attr

from twisted.python.failure import Failure
from twisted.web.client import ResponseDone

TV = TypeVar("TV")


def get_awaitable_result(awaitable: Awaitable[TV]) -> TV:
    """Get the result from an Awaitable which should have completed

    Asserts that the given awaitable has a result ready, and returns its value
    """
    i = awaitable.__await__()
    try:
        next(i)
    except StopIteration as e:
        # awaitable returned a result
        return e.value

    # if next didn't raise, the awaitable hasn't completed.
    raise Exception("awaitable has not yet completed")


def make_awaitable(result: Any) -> Awaitable[Any]:
    """
    Makes an awaitable, suitable for mocking an `async` function.
    This uses Futures as they can be awaited multiple times so can be returned
    to multiple callers.
    """
    future = Future()  # type: ignore
    future.set_result(result)
    return future


def setup_awaitable_errors() -> Callable[[], None]:
    """
    Convert warnings from a non-awaited coroutines into errors.
    """
    warnings.simplefilter("error", RuntimeWarning)

    # unraisablehook was added in Python 3.8.
    if not hasattr(sys, "unraisablehook"):
        return lambda: None

    # State shared between unraisablehook and check_for_unraisable_exceptions.
    unraisable_exceptions = []
    orig_unraisablehook = sys.unraisablehook  # type: ignore

    def unraisablehook(unraisable):
        unraisable_exceptions.append(unraisable.exc_value)

    def cleanup():
        """
        A method to be used as a clean-up that fails a test-case if there are any new unraisable exceptions.
        """
        sys.unraisablehook = orig_unraisablehook  # type: ignore
        if unraisable_exceptions:
            raise unraisable_exceptions.pop()

    sys.unraisablehook = unraisablehook  # type: ignore

    return cleanup


def simple_async_mock(return_value=None, raises=None) -> Mock:
    # AsyncMock is not available in python3.5, this mimics part of its behaviour
    async def cb(*args, **kwargs):
        if raises:
            raise raises
        return return_value

    return Mock(side_effect=cb)


@attr.s
class FakeResponse:
    """A fake twisted.web.IResponse object

    there is a similar class at treq.test.test_response, but it lacks a `phrase`
    attribute, and didn't support deliverBody until recently.
    """

    # HTTP response code
    code = attr.ib(type=int)

    # HTTP response phrase (eg b'OK' for a 200)
    phrase = attr.ib(type=bytes)

    # body of the response
    body = attr.ib(type=bytes)

    def deliverBody(self, protocol):
        protocol.dataReceived(self.body)
        protocol.connectionLost(Failure(ResponseDone()))
