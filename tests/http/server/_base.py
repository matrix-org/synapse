# Copyright 2022 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unles4s required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import inspect
import itertools
import logging
from http import HTTPStatus
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from unittest import mock

from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectionDone
from twisted.python.failure import Failure

from synapse.http.server import (
    HTTP_STATUS_REQUEST_CANCELLED,
    respond_with_html_bytes,
    respond_with_json,
)
from synapse.http.site import SynapseRequest
from synapse.logging.context import LoggingContext, make_deferred_yieldable
from synapse.types import JsonDict

from tests import unittest
from tests.server import FakeChannel, ThreadedMemoryReactorClock
from tests.unittest import logcontext_clean

logger = logging.getLogger(__name__)


T = TypeVar("T")


class EndpointCancellationTestHelperMixin(unittest.TestCase):
    """Provides helper methods for testing cancellation of endpoints."""

    def _test_disconnect(
        self,
        reactor: ThreadedMemoryReactorClock,
        channel: FakeChannel,
        expect_cancellation: bool,
        expected_body: Union[bytes, JsonDict],
        expected_code: Optional[int] = None,
    ) -> None:
        """Disconnects an in-flight request and checks the response.

        Args:
            reactor: The twisted reactor running the request handler.
            channel: The `FakeChannel` for the request.
            expect_cancellation: `True` if request processing is expected to be
                cancelled, `False` if the request should run to completion.
            expected_body: The expected response for the request.
            expected_code: The expected status code for the request. Defaults to `200`
                or `499` depending on `expect_cancellation`.
        """
        # Determine the expected status code.
        if expected_code is None:
            if expect_cancellation:
                expected_code = HTTP_STATUS_REQUEST_CANCELLED
            else:
                expected_code = HTTPStatus.OK

        request = channel.request
        self.assertFalse(
            channel.is_finished(),
            "Request finished before we could disconnect - "
            "was `await_result=False` passed to `make_request`?",
        )

        # We're about to disconnect the request. This also disconnects the channel, so
        # we have to rely on mocks to extract the response.
        respond_method: Callable[..., Any]
        if isinstance(expected_body, bytes):
            respond_method = respond_with_html_bytes
        else:
            respond_method = respond_with_json

        with mock.patch(
            f"synapse.http.server.{respond_method.__name__}", wraps=respond_method
        ) as respond_mock:
            # Disconnect the request.
            request.connectionLost(reason=ConnectionDone())

            if expect_cancellation:
                # An immediate cancellation is expected.
                respond_mock.assert_called_once()
                args, _kwargs = respond_mock.call_args
                code, body = args[1], args[2]
                self.assertEqual(code, expected_code)
                self.assertEqual(request.code, expected_code)
                self.assertEqual(body, expected_body)
            else:
                respond_mock.assert_not_called()

                # The handler is expected to run to completion.
                reactor.pump([1.0])
                respond_mock.assert_called_once()
                args, _kwargs = respond_mock.call_args
                code, body = args[1], args[2]
                self.assertEqual(code, expected_code)
                self.assertEqual(request.code, expected_code)
                self.assertEqual(body, expected_body)

    @logcontext_clean
    def _test_cancellation_at_every_await(
        self,
        reactor: ThreadedMemoryReactorClock,
        make_request: Callable[[], FakeChannel],
        test_name: str,
        expected_code: int = HTTPStatus.OK,
    ) -> JsonDict:
        """Performs a request repeatedly, disconnecting at successive `await`s, until
        one completes.

        Fails if:
            * A logging context is lost during cancellation.
            * A logging context get restarted after it is marked as finished, eg. if
              a request's logging context is used by some processing started by the
              request, but the request neglects to cancel that processing or wait for it
              to complete.

              Note that "Re-starting finished log context" errors get caught by twisted
              and will manifest in a different logging context error at a later point.
              When debugging logging context failures, setting a breakpoint in
              `logcontext_error` can prove useful.
            * A request gets stuck, possibly due to a previous cancellation.
            * The request does not return a 499 when the client disconnects.
              This implies that a `CancelledError` was swallowed somewhere.
            * The request does not return a 200 when allowed to run to completion.

        It is up to the caller to verify that the request returns the correct data when
        it finally runs to completion.

        Note that this function can only cover a single code path and does not guarantee
        that an endpoint is compatible with cancellation on every code path.
        To allow inspection of the code path that is being tested, this function will
        log the stack trace at every `await` that gets cancelled. To view these log
        lines, `trial` can be run with the `SYNAPSE_TEST_LOG_LEVEL=INFO` environment
        variable, which will include the log lines in `_trial_temp/test.log`.
        Alternatively, `_log_for_request` can be modified to write to `sys.stdout`.

        Args:
            reactor: The twisted reactor running the request handler.
            make_request: A function that initiates the request and returns a
                `FakeChannel`.
            test_name: The name of the test, which will be logged.
            expected_code: The expected status code for the final request that runs to
                completion. Defaults to `200`.

        Returns:
            The JSON response of the final request that runs to completion.
        """
        # To process a request, a coroutine run is created for the async method handling
        # the request. That method may then start other coroutine runs, wrapped in
        # `Deferred`s.
        #
        # We would like to trigger a cancellation at the first `await`, re-run the
        # request and cancel at the second `await`, and so on. By patching
        # `Deferred.__next__`, we can intercept `await`s, track which ones we have or
        # have not seen, and force them to block when they wouldn't have.

        # The set of previously seen `await`s.
        # Each element is a stringified stack trace.
        seen_awaits: Set[Tuple[str, ...]] = set()

        self._log_for_request(
            0, f"Running _test_cancellation_at_every_await for {test_name}..."
        )

        for request_number in itertools.count(1):
            (
                Deferred___next__,
                unblock_awaits,
                get_awaits_seen,
                has_seen_new_await,
            ) = self.create_deferred___next___patch(seen_awaits, request_number)

            try:
                with mock.patch(
                    "synapse.http.server.respond_with_json", wraps=respond_with_json
                ) as respond_mock:
                    with mock.patch.object(
                        Deferred,
                        "__next__",
                        new=Deferred___next__,
                    ):
                        # Start the request.
                        channel = make_request()
                        request = channel.request

                        if request_number == 0:
                            self.assertFalse(
                                respond_mock.called,
                                "Request finished before we could disconnect - "
                                "was `await_result=False` passed to `make_request`?",
                            )
                        else:
                            # Requests after the first may be lucky enough to hit caches
                            # all the way through and never have to block.
                            pass

                        # Run the request until we see a new `await` which we have not
                        # yet cancelled at, or it completes.
                        while not respond_mock.called and not has_seen_new_await():
                            previous_awaits_seen = get_awaits_seen()

                            reactor.pump([0.0])

                            if get_awaits_seen() == previous_awaits_seen:
                                # We didn't see any progress. Try advancing the clock.
                                reactor.pump([1.0])

                            if get_awaits_seen() == previous_awaits_seen:
                                # We still didn't see any progress. The request might be stuck.
                                self.fail(
                                    "Request appears to be stuck, possibly due to "
                                    "a previous cancelled request"
                                )

                    if respond_mock.called:
                        # The request ran to completion and we are done with testing it.

                        # `respond_with_json` writes the response asynchronously, so we
                        # might have to give the reactor a kick before the channel gets
                        # the response.
                        reactor.pump([1.0])

                        self.assertEqual(channel.code, expected_code)
                        return channel.json_body
                    else:
                        # Disconnect the client and wait for the response.
                        request.connectionLost(reason=ConnectionDone())

                        self._log_for_request(request_number, "--- disconnected ---")

                        # We may need to pump the reactor to allow `delay_cancellation`s
                        # to finish.
                        if not respond_mock.called:
                            reactor.pump([0.0])

                        # Try advancing the clock if that didn't work.
                        if not respond_mock.called:
                            reactor.pump([1.0])

                        # Mark the request's logging context as finished. If it gets
                        # activated again, an `AssertionError` will be raised. This
                        # `AssertionError` will likely be caught by twisted and turned
                        # into a `Failure`. Instead, a different `AssertionError` will
                        # be observed when the logging context is deactivated, as it
                        # wouldn't have tracked resource usage correctly.
                        if isinstance(request, SynapseRequest) and request.logcontext:
                            request.logcontext.finished = True

                        # Check that the request finished with a 499,
                        # ie. the `CancelledError` wasn't swallowed.
                        respond_mock.assert_called_once()
                        args, _kwargs = respond_mock.call_args
                        code = args[1]
                        self.assertEqual(code, HTTP_STATUS_REQUEST_CANCELLED)
            finally:
                # Unblock any processing that might be shared between requests.
                unblock_awaits()

        assert False, "unreachable"  # noqa: B011

    def create_deferred___next___patch(
        self, seen_awaits: Set[Tuple[str, ...]], request_number: int
    ) -> Tuple[
        Callable[["Deferred[T]"], "Deferred[T]"],
        Callable[[], None],
        Callable[[], int],
        Callable[[], bool],
    ]:
        """Creates a function to patch `Deferred.__next__` with, for
        `_test_cancellation_at_every_await`.

        Produces a `Deferred.__next__` patch that will intercept `await`s and force them
        to block once it sees a new `await`.

        Args:
            seen_awaits: The set of stack traces of `await`s that have been previously
                seen. When the `Deferred.__next__` patch sees a new `await`, it will add
                it to the set.
            request_number: The request number to log against.

        Returns:
            A tuple containing:
             * The method to replace `Deferred.__next__` with.
             * A method that will clean up after any `await`s that were forced to block.
               This method must be called when done, otherwise processing shared between
               multiple requests, such as database queries started by `@cached`, will
               become permanently stuck.
             * A method returning the running total of intercepted `await`s on
               `Deferred`s.
             * A method returning `True` once a new `await` has been seen.
        """
        original_Deferred___next__ = Deferred.__next__

        # The number of `await`s on `Deferred`s we have seen so far.
        awaits_seen = 0

        # Whether we have seen a new `await` not in `seen_awaits`.
        new_await_seen = False

        # To force `await`s on resolved `Deferred`s to block, we make up a new
        # unresolved `Deferred` and return it out of `Deferred.__next__` /
        # `coroutine.send()`. We have to resolve it later, in case the
        # `await`ing coroutine is part of some shared processing, such as
        # `@cached`.
        to_unblock: Dict[Deferred, Union[object, Failure]] = {}

        # The last stack we logged.
        previous_stack: List[inspect.FrameInfo] = []

        def unblock_awaits() -> None:
            """Unblocks any shared processing that we forced to block."""
            for deferred, result in to_unblock.items():
                deferred.callback(result)

        def get_awaits_seen() -> int:
            return awaits_seen

        def has_seen_new_await() -> bool:
            return new_await_seen

        def Deferred___next__(
            deferred: "Deferred[T]", value: object = None
        ) -> "Deferred[T]":
            """Intercepts `await`s on `Deferred`s and rigs them to block once we have
            seen enough of them.

            `Deferred.__next__` will normally:
                * return `self` if unresolved, which will come out of
                    `coroutine.send()`.
                * raise a `StopIteration(result)`, containing the result of the
                    `await`.
                * raise another exception, which will come out of the `await`.
            """
            nonlocal awaits_seen
            nonlocal new_await_seen
            nonlocal previous_stack

            awaits_seen += 1

            stack = self._get_stack(skip_frames=1)
            stack_hash = self._hash_stack(stack)

            if stack_hash not in seen_awaits:
                # Block at the current `await` onwards.
                seen_awaits.add(stack_hash)
                new_await_seen = True

            if not new_await_seen:
                # This `await` isn't interesting. Let it proceed normally.

                # Don't log the stack. It's been seen before in a previous run.
                previous_stack = stack

                return original_Deferred___next__(deferred, value)
            else:
                # We want to block at the current `await`.
                if deferred.called and not deferred.paused:
                    # This `Deferred` already has a result.
                    # We return a new, unresolved, `Deferred` for `_inlineCallbacks`
                    # to wait on. This blocks the coroutine that did this `await`.
                    # We queue it up for unblocking later.
                    new_deferred: "Deferred[T]" = Deferred()
                    to_unblock[new_deferred] = deferred.result

                    self._log_await_stack(
                        stack, previous_stack, request_number, "force-blocked await"
                    )
                    previous_stack = stack

                    return make_deferred_yieldable(new_deferred)
                else:
                    # This `Deferred` does not have a result yet.
                    # The `await` will block normally, so we don't have to do
                    # anything.
                    self._log_await_stack(
                        stack, previous_stack, request_number, "blocking await"
                    )
                    previous_stack = stack

                    return original_Deferred___next__(deferred, value)

        return Deferred___next__, unblock_awaits, get_awaits_seen, has_seen_new_await

    def _log_for_request(self, request_number: int, message: str) -> None:
        """Logs a message for an iteration of `_test_cancellation_at_every_await`."""
        # We want consistent alignment when logging stack traces, so ensure the
        # logging context has a fixed width name.
        with LoggingContext(name=f"request-{request_number:<2}"):
            logger.info(message)

    def _log_await_stack(
        self,
        stack: List[inspect.FrameInfo],
        previous_stack: List[inspect.FrameInfo],
        request_number: int,
        note: str,
    ) -> None:
        """Logs the stack for an `await` in `_test_cancellation_at_every_await`.

        Only logs the part of the stack that has changed since the previous call.

        Example output looks like:
        ```
        delay_cancellation:750 (synapse/util/async_helpers.py:750)
            DatabasePool._runInteraction:768 (synapse/storage/database.py:768)
                > *blocked on await* at DatabasePool.runWithConnection:891 (synapse/storage/database.py:891)
        ```

        Args:
            stack: The stack to log, as returned by `_get_stack()`.
            previous_stack: The previous stack logged, with callers appearing before
                callees.
            request_number: The request number to log against.
            note: A note to attach to the last stack frame, eg. "blocked on await".
        """
        for i, frame_info in enumerate(stack[:-1]):
            # Skip any frames in common with the previous logging.
            if i < len(previous_stack) and frame_info == previous_stack[i]:
                continue

            frame = self._format_stack_frame(frame_info)
            message = f"{'  ' * i}{frame}"
            self._log_for_request(request_number, message)

        # Always print the final frame with the `await`.
        # If the frame with the `await` started another coroutine run, we may have
        # already printed a deeper stack which includes our final frame. We want to
        # log where all `await`s happen, so we reprint the frame in this case.
        i = len(stack) - 1
        frame_info = stack[i]
        frame = self._format_stack_frame(frame_info)
        message = f"{'  ' * i}> *{note}* at {frame}"
        self._log_for_request(request_number, message)

    def _format_stack_frame(self, frame_info: inspect.FrameInfo) -> str:
        """Returns a string representation of a stack frame.

        Used for debug logging.

        Returns:
            A string, formatted like
            "JsonResource._async_render:559 (synapse/http/server.py:559)".
        """
        method_name = self._get_stack_frame_method_name(frame_info)

        return (
            f"{method_name}:{frame_info.lineno} "
            f"({frame_info.filename}:{frame_info.lineno})"
        )

    def _get_stack(self, skip_frames: int) -> List[inspect.FrameInfo]:
        """Captures the stack for a request.

        Skips any twisted frames and stops at `JsonResource.wrapped_async_request_handler`.

        Used for debug logging.

        Returns:
            A list of `inspect.FrameInfo`s, with callers appearing before callees.
        """
        stack = []

        skip_frames += 1  # Also skip `get_stack` itself.

        for frame_info in inspect.stack()[skip_frames:]:
            # Skip any twisted `inlineCallbacks` gunk.
            if "/twisted/" in frame_info.filename:
                continue

            # Exclude the reactor frame, upwards.
            method_name = self._get_stack_frame_method_name(frame_info)
            if method_name == "ThreadedMemoryReactorClock.advance":
                break

            stack.append(frame_info)

            # Stop at `JsonResource`'s `wrapped_async_request_handler`, which is the
            # entry point for request handling.
            if frame_info.function == "wrapped_async_request_handler":
                break

        return stack[::-1]

    def _get_stack_frame_method_name(self, frame_info: inspect.FrameInfo) -> str:
        """Returns the name of a stack frame's method.

        eg. "JsonResource._async_render".
        """
        method_name = frame_info.function

        # Prefix the class name for instance methods.
        frame_self = frame_info.frame.f_locals.get("self")
        if frame_self:
            method = getattr(frame_self, method_name, None)
            if method:
                method_name = method.__qualname__
            else:
                # We couldn't find the method on `self`.
                # Make something up. It's useful to know which class "contains" a
                # function anyway.
                method_name = f"{type(frame_self).__name__} {method_name}"

        return method_name

    def _hash_stack(self, stack: List[inspect.FrameInfo]):
        """Turns a stack into a hashable value that can be put into a set."""
        return tuple(self._format_stack_frame(frame) for frame in stack)
