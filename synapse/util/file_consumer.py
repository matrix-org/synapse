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

import queue
from typing import BinaryIO, Optional, Union, cast

from twisted.internet import threads
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IPullProducer, IPushProducer

from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.types import ISynapseReactor


class BackgroundFileConsumer:
    """A consumer that writes to a file like object. Supports both push
    and pull producers

    Args:
        file_obj: The file like object to write to. Closed when
            finished.
        reactor: the Twisted reactor to use
    """

    # For PushProducers pause if we have this many unwritten slices
    _PAUSE_ON_QUEUE_SIZE = 5
    # And resume once the size of the queue is less than this
    _RESUME_ON_QUEUE_SIZE = 2

    def __init__(self, file_obj: BinaryIO, reactor: ISynapseReactor) -> None:
        self._file_obj: BinaryIO = file_obj

        self._reactor: ISynapseReactor = reactor

        # Producer we're registered with
        self._producer: Optional[Union[IPushProducer, IPullProducer]] = None

        # True if PushProducer, false if PullProducer
        self.streaming = False

        # For PushProducers, indicates whether we've paused the producer and
        # need to call resumeProducing before we get more data.
        self._paused_producer = False

        # Queue of slices of bytes to be written. When producer calls
        # unregister a final None is sent.
        self._bytes_queue: queue.Queue[Optional[bytes]] = queue.Queue()

        # Deferred that is resolved when finished writing
        self._finished_deferred: Optional[Deferred[None]] = None

        # If the _writer thread throws an exception it gets stored here.
        self._write_exception: Optional[Exception] = None

    def registerProducer(
        self, producer: Union[IPushProducer, IPullProducer], streaming: bool
    ) -> None:
        """Part of IConsumer interface

        Args:
            producer
            streaming: True if push based producer, False if pull
                based.
        """
        if self._producer:
            raise Exception("registerProducer called twice")

        self._producer = producer
        self.streaming = streaming
        self._finished_deferred = run_in_background(
            threads.deferToThreadPool,
            self._reactor,
            self._reactor.getThreadPool(),
            self._writer,
        )
        if not streaming:
            self._producer.resumeProducing()

    def unregisterProducer(self) -> None:
        """Part of IProducer interface"""
        self._producer = None
        assert self._finished_deferred is not None
        if not self._finished_deferred.called:
            self._bytes_queue.put_nowait(None)

    def write(self, write_bytes: bytes) -> None:
        """Part of IProducer interface"""
        if self._write_exception:
            raise self._write_exception

        assert self._finished_deferred is not None
        if self._finished_deferred.called:
            raise Exception("consumer has closed")

        self._bytes_queue.put_nowait(write_bytes)

        # If this is a PushProducer and the queue is getting behind
        # then we pause the producer.
        if self.streaming and self._bytes_queue.qsize() >= self._PAUSE_ON_QUEUE_SIZE:
            self._paused_producer = True
            assert self._producer is not None
            # cast safe because `streaming` means this is an IPushProducer
            cast(IPushProducer, self._producer).pauseProducing()

    def _writer(self) -> None:
        """This is run in a background thread to write to the file."""
        try:
            while self._producer or not self._bytes_queue.empty():
                # If we've paused the producer check if we should resume the
                # producer.
                if self._producer and self._paused_producer:
                    if self._bytes_queue.qsize() <= self._RESUME_ON_QUEUE_SIZE:
                        self._reactor.callFromThread(self._resume_paused_producer)

                bytes = self._bytes_queue.get()

                # If we get a None (or empty list) then that's a signal used
                # to indicate we should check if we should stop.
                if bytes:
                    self._file_obj.write(bytes)

                # If its a pull producer then we need to explicitly ask for
                # more stuff.
                if not self.streaming and self._producer:
                    self._reactor.callFromThread(self._producer.resumeProducing)
        except Exception as e:
            self._write_exception = e
            raise
        finally:
            self._file_obj.close()

    def wait(self) -> "Deferred[None]":
        """Returns a deferred that resolves when finished writing to file"""
        assert self._finished_deferred is not None
        return make_deferred_yieldable(self._finished_deferred)

    def _resume_paused_producer(self) -> None:
        """Gets called if we should resume producing after being paused"""
        if self._paused_producer and self._producer:
            self._paused_producer = False
            self._producer.resumeProducing()
