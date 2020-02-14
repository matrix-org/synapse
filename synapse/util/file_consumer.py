# -*- coding: utf-8 -*-
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

from six.moves import queue

from twisted.internet import threads

from synapse.logging.context import make_deferred_yieldable, run_in_background


class BackgroundFileConsumer(object):
    """A consumer that writes to a file like object. Supports both push
    and pull producers

    Args:
        file_obj (file): The file like object to write to. Closed when
            finished.
        reactor (twisted.internet.reactor): the Twisted reactor to use
    """

    # For PushProducers pause if we have this many unwritten slices
    _PAUSE_ON_QUEUE_SIZE = 5
    # And resume once the size of the queue is less than this
    _RESUME_ON_QUEUE_SIZE = 2

    def __init__(self, file_obj, reactor):
        self._file_obj = file_obj

        self._reactor = reactor

        # Producer we're registered with
        self._producer = None

        # True if PushProducer, false if PullProducer
        self.streaming = False

        # For PushProducers, indicates whether we've paused the producer and
        # need to call resumeProducing before we get more data.
        self._paused_producer = False

        # Queue of slices of bytes to be written. When producer calls
        # unregister a final None is sent.
        self._bytes_queue = queue.Queue()

        # Deferred that is resolved when finished writing
        self._finished_deferred = None

        # If the _writer thread throws an exception it gets stored here.
        self._write_exception = None

    def registerProducer(self, producer, streaming):
        """Part of IConsumer interface

        Args:
            producer (IProducer)
            streaming (bool): True if push based producer, False if pull
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

    def unregisterProducer(self):
        """Part of IProducer interface
        """
        self._producer = None
        if not self._finished_deferred.called:
            self._bytes_queue.put_nowait(None)

    def write(self, bytes):
        """Part of IProducer interface
        """
        if self._write_exception:
            raise self._write_exception

        if self._finished_deferred.called:
            raise Exception("consumer has closed")

        self._bytes_queue.put_nowait(bytes)

        # If this is a PushProducer and the queue is getting behind
        # then we pause the producer.
        if self.streaming and self._bytes_queue.qsize() >= self._PAUSE_ON_QUEUE_SIZE:
            self._paused_producer = True
            self._producer.pauseProducing()

    def _writer(self):
        """This is run in a background thread to write to the file.
        """
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

    def wait(self):
        """Returns a deferred that resolves when finished writing to file
        """
        return make_deferred_yieldable(self._finished_deferred)

    def _resume_paused_producer(self):
        """Gets called if we should resume producing after being paused
        """
        if self._paused_producer and self._producer:
            self._paused_producer = False
            self._producer.resumeProducing()
