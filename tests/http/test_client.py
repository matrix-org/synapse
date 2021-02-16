#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from io import BytesIO

from mock import Mock

from twisted.python.failure import Failure
from twisted.web.client import ResponseDone
from twisted.web.iweb import UNKNOWN_LENGTH

from synapse.http.client import BodyExceededMaxSize, read_body_with_max_size

from tests.unittest import TestCase


class ReadBodyWithMaxSizeTests(TestCase):
    def setUp(self):
        """Start reading the body, returns the response, result and proto"""
        response = Mock(length=UNKNOWN_LENGTH)
        self.result = BytesIO()
        self.deferred = read_body_with_max_size(response, self.result, 6)

        # Fish the protocol out of the response.
        self.protocol = response.deliverBody.call_args[0][0]
        self.protocol.transport = Mock()

    def _cleanup_error(self):
        """Ensure that the error in the Deferred is handled gracefully."""
        called = [False]

        def errback(f):
            called[0] = True

        self.deferred.addErrback(errback)
        self.assertTrue(called[0])

    def test_no_error(self):
        """A response that is NOT too large."""

        # Start sending data.
        self.protocol.dataReceived(b"12345")
        # Close the connection.
        self.protocol.connectionLost(Failure(ResponseDone()))

        self.assertEqual(self.result.getvalue(), b"12345")
        self.assertEqual(self.deferred.result, 5)

    def test_too_large(self):
        """A response which is too large raises an exception."""

        # Start sending data.
        self.protocol.dataReceived(b"1234567890")
        # Close the connection.
        self.protocol.connectionLost(Failure(ResponseDone()))

        self.assertEqual(self.result.getvalue(), b"1234567890")
        self.assertIsInstance(self.deferred.result, Failure)
        self.assertIsInstance(self.deferred.result.value, BodyExceededMaxSize)
        self._cleanup_error()

    def test_multiple_packets(self):
        """Data should be accummulated through mutliple packets."""

        # Start sending data.
        self.protocol.dataReceived(b"12")
        self.protocol.dataReceived(b"34")
        # Close the connection.
        self.protocol.connectionLost(Failure(ResponseDone()))

        self.assertEqual(self.result.getvalue(), b"1234")
        self.assertEqual(self.deferred.result, 4)

    def test_additional_data(self):
        """A connection can receive data after being closed."""

        # Start sending data.
        self.protocol.dataReceived(b"1234567890")
        self.assertIsInstance(self.deferred.result, Failure)
        self.assertIsInstance(self.deferred.result.value, BodyExceededMaxSize)
        self.protocol.transport.abortConnection.assert_called_once()

        # More data might have come in.
        self.protocol.dataReceived(b"1234567890")
        # Close the connection.
        self.protocol.connectionLost(Failure(ResponseDone()))

        self.assertEqual(self.result.getvalue(), b"1234567890")
        self.assertIsInstance(self.deferred.result, Failure)
        self.assertIsInstance(self.deferred.result.value, BodyExceededMaxSize)
        self._cleanup_error()
