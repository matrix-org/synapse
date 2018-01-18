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

from twisted.internet import defer, threads, reactor

from synapse.util.logcontext import make_deferred_yieldable

import Queue


class BackgroundFileConsumer(object):
    """A consumer that writes to a file like object. Supports both push
    and pull producers

    Args:
        file_obj (file): The file like object to write to. Closed when
            finished.
    """

    # For PushProducers pause if we have this many unwritten slices
    _PAUSE_ON_QUEUE_SIZE = 5
    # And resume once the size of the queue is less than this
    _RESUME_ON_QUEUE_SIZE = 2

    def __init__(self, file_obj):
        self.file_obj = file_obj

        # Producer we're registered with
        self.producer = None

        # True if PushProducer, false if PullProducer
        self.streaming = False

        # For PushProducers, indicates whether we've paused the producer and
        # need to call resumeProducing before we get more data.
        self.paused_producer = False

        # Queue of slices of bytes to be written. When producer calls
        # unregister a final None is sent.
        self.bytes_queue = Queue.Queue()

        # Deferred that is resolved when finished writing
        self.finished_deferred = None

        # If the _writer thread throws an exception it gets stored here.
        self._write_exception = None

        # A deferred that gets resolved when the bytes_queue gets empty.
        # Mainly used for tests.
        self._notify_empty_deferred = None

    def registerProducer(self, producer, streaming):
        """Part of IConsumer interface

        Args:
            producer (IProducer)
            streaming (bool): True if push based producer, False if pull
                based.
        """
        self.producer = producer
        self.streaming = streaming
        self.finished_deferred = threads.deferToThread(self._writer)
        if not streaming:
            self.producer.resumeProducing()

    def unregisterProducer(self):
        """Part of IProducer interface
        """
        self.producer = None
        if not self.finished_deferred.called:
            self.bytes_queue.put_nowait(None)

    def write(self, bytes):
        """Part of IProducer interface
        """
        if self._write_exception:
            raise self._write_exception

        if self.finished_deferred.called:
            raise Exception("consumer has closed")

        self.bytes_queue.put_nowait(bytes)

        # If this is a PushProducer and the queue is getting behind
        # then we pause the producer.
        if self.streaming and self.bytes_queue.qsize() >= self._PAUSE_ON_QUEUE_SIZE:
            self.paused_producer = True
            self.producer.pauseProducing()

    def _writer(self):
        """This is run in a background thread to write to the file.
        """
        try:
            while self.producer or not self.bytes_queue.empty():
                # If we've paused the producer check if we should resume the
                # producer.
                if self.producer and self.paused_producer:
                    if self.bytes_queue.qsize() <= self._RESUME_ON_QUEUE_SIZE:
                        reactor.callFromThread(self._resume_paused_producer)

                if self._notify_empty and self.bytes_queue.empty():
                    reactor.callFromThread(self._notify_empty)

                bytes = self.bytes_queue.get()

                # If we get a None (or empty list) then that's a signal used
                # to indicate we should check if we should stop.
                if bytes:
                    self.file_obj.write(bytes)

                # If its a pull producer then we need to explicitly ask for
                # more stuff.
                if not self.streaming and self.producer:
                    reactor.callFromThread(self.producer.resumeProducing)
        except Exception as e:
            self._write_exception = e
            raise
        finally:
            self.file_obj.close()

    def wait(self):
        """Returns a deferred that resolves when finished writing to file
        """
        return make_deferred_yieldable(self.finished_deferred)

    def _resume_paused_producer(self):
        """Gets called if we should resume producing after being paused
        """
        if self.paused_producer and self.producer:
            self.paused_producer = False
            self.producer.resumeProducing()

    def _notify_empty(self):
        """Called when the _writer thread thinks the queue may be empty and
        we should notify anything waiting on `wait_for_writes`
        """
        if self._notify_empty_deferred and self.bytes_queue.empty():
            d = self._notify_empty_deferred
            self._notify_empty_deferred = None
            d.callback(None)

    def wait_for_writes(self):
        """Wait for the write queue to be empty and for writes to have
        finished. This is mainly useful for tests.
        """
        if not self._notify_empty_deferred:
            self._notify_empty_deferred = defer.Deferred()
        return self._notify_empty_deferred
