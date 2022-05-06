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

from http import HTTPStatus
from typing import Any, Callable, Optional, Union
from unittest import mock

from twisted.internet.error import ConnectionDone

from synapse.http.server import (
    HTTP_STATUS_REQUEST_CANCELLED,
    respond_with_html_bytes,
    respond_with_json,
)
from synapse.types import JsonDict

from tests import unittest
from tests.server import FakeChannel, ThreadedMemoryReactorClock


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
