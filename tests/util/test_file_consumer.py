# Copyright 2018 New Vector Ltd
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


import threading
from io import StringIO
from unittest.mock import NonCallableMock

from twisted.internet import defer, reactor

from synapse.util.file_consumer import BackgroundFileConsumer

from tests import unittest


class FileConsumerTests(unittest.TestCase):
    @defer.inlineCallbacks
    def test_pull_consumer(self):
        string_file = StringIO()
        consumer = BackgroundFileConsumer(string_file, reactor=reactor)

        try:
            producer = DummyPullProducer()

            yield producer.register_with_consumer(consumer)

            yield producer.write_and_wait("Foo")

            self.assertEqual(string_file.getvalue(), "Foo")

            yield producer.write_and_wait("Bar")

            self.assertEqual(string_file.getvalue(), "FooBar")
        finally:
            consumer.unregisterProducer()

        yield consumer.wait()

        self.assertTrue(string_file.closed)

    @defer.inlineCallbacks
    def test_push_consumer(self):
        string_file = BlockingStringWrite()
        consumer = BackgroundFileConsumer(string_file, reactor=reactor)

        try:
            producer = NonCallableMock(spec_set=[])

            consumer.registerProducer(producer, True)

            consumer.write("Foo")
            yield string_file.wait_for_n_writes(1)

            self.assertEqual(string_file.buffer, "Foo")

            consumer.write("Bar")
            yield string_file.wait_for_n_writes(2)

            self.assertEqual(string_file.buffer, "FooBar")
        finally:
            consumer.unregisterProducer()

        yield consumer.wait()

        self.assertTrue(string_file.closed)

    @defer.inlineCallbacks
    def test_push_producer_feedback(self):
        string_file = BlockingStringWrite()
        consumer = BackgroundFileConsumer(string_file, reactor=reactor)

        try:
            producer = NonCallableMock(spec_set=["pauseProducing", "resumeProducing"])

            resume_deferred = defer.Deferred()
            producer.resumeProducing.side_effect = lambda: resume_deferred.callback(
                None
            )

            consumer.registerProducer(producer, True)

            number_writes = 0
            with string_file.write_lock:
                for _ in range(consumer._PAUSE_ON_QUEUE_SIZE):
                    consumer.write("Foo")
                    number_writes += 1

                producer.pauseProducing.assert_called_once()

            yield string_file.wait_for_n_writes(number_writes)

            yield resume_deferred
            producer.resumeProducing.assert_called_once()
        finally:
            consumer.unregisterProducer()

        yield consumer.wait()

        self.assertTrue(string_file.closed)


class DummyPullProducer:
    def __init__(self):
        self.consumer = None
        self.deferred = defer.Deferred()

    def resumeProducing(self):
        d = self.deferred
        self.deferred = defer.Deferred()
        d.callback(None)

    def write_and_wait(self, bytes):
        d = self.deferred
        self.consumer.write(bytes)
        return d

    def register_with_consumer(self, consumer):
        d = self.deferred
        self.consumer = consumer
        self.consumer.registerProducer(self, False)
        return d


class BlockingStringWrite:
    def __init__(self):
        self.buffer = ""
        self.closed = False
        self.write_lock = threading.Lock()

        self._notify_write_deferred = None
        self._number_of_writes = 0

    def write(self, bytes):
        with self.write_lock:
            self.buffer += bytes
            self._number_of_writes += 1

        reactor.callFromThread(self._notify_write)

    def close(self):
        self.closed = True

    def _notify_write(self):
        "Called by write to indicate a write happened"
        with self.write_lock:
            if not self._notify_write_deferred:
                return
            d = self._notify_write_deferred
            self._notify_write_deferred = None
        d.callback(None)

    @defer.inlineCallbacks
    def wait_for_n_writes(self, n):
        "Wait for n writes to have happened"
        while True:
            with self.write_lock:
                if n <= self._number_of_writes:
                    return

                if not self._notify_write_deferred:
                    self._notify_write_deferred = defer.Deferred()

                d = self._notify_write_deferred

            yield d
