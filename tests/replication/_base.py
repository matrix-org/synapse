# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

import logging
from typing import Any, Callable, List, Optional, Tuple

import attr

from twisted.internet.interfaces import IConsumer, IPullProducer, IReactorTime
from twisted.internet.task import LoopingCall
from twisted.web.http import HTTPChannel

from synapse.app.generic_worker import (
    GenericWorkerReplicationHandler,
    GenericWorkerServer,
)
from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest
from synapse.replication.http import ReplicationRestResource, streams
from synapse.replication.tcp.handler import ReplicationCommandHandler
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.server import FakeTransport, render

logger = logging.getLogger(__name__)


class BaseStreamTestCase(unittest.HomeserverTestCase):
    """Base class for tests of the replication streams"""

    servlets = [
        streams.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        # build a replication server
        server_factory = ReplicationStreamProtocolFactory(hs)
        self.streamer = hs.get_replication_streamer()
        self.server = server_factory.buildProtocol(None)

        # Make a new HomeServer object for the worker
        self.reactor.lookups["testserv"] = "1.2.3.4"
        self.worker_hs = self.setup_test_homeserver(
            http_client=None,
            homeserverToUse=GenericWorkerServer,
            config=self._get_worker_hs_config(),
            reactor=self.reactor,
        )

        # Since we use sqlite in memory databases we need to make sure the
        # databases objects are the same.
        self.worker_hs.get_datastore().db_pool = hs.get_datastore().db_pool

        self.test_handler = self._build_replication_data_handler()
        self.worker_hs.replication_data_handler = self.test_handler

        repl_handler = ReplicationCommandHandler(self.worker_hs)
        self.client = ClientReplicationStreamProtocol(
            self.worker_hs, "client", "test", clock, repl_handler,
        )

        self._client_transport = None
        self._server_transport = None

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_app"] = "synapse.app.generic_worker"
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"
        return config

    def _build_replication_data_handler(self):
        return TestReplicationDataHandler(self.worker_hs)

    def reconnect(self):
        if self._client_transport:
            self.client.close()

        if self._server_transport:
            self.server.close()

        self._client_transport = FakeTransport(self.server, self.reactor)
        self.client.makeConnection(self._client_transport)

        self._server_transport = FakeTransport(self.client, self.reactor)
        self.server.makeConnection(self._server_transport)

    def disconnect(self):
        if self._client_transport:
            self._client_transport = None
            self.client.close()

        if self._server_transport:
            self._server_transport = None
            self.server.close()

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump(0.1)

    def handle_http_replication_attempt(self) -> SynapseRequest:
        """Asserts that a connection attempt was made to the master HS on the
        HTTP replication port, then proxies it to the master HS object to be
        handled.

        Returns:
            The request object received by master HS.
        """

        # We should have an outbound connection attempt.
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients.pop(0)
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8765)

        # Set up client side protocol
        client_protocol = client_factory.buildProtocol(None)

        request_factory = OneShotRequestFactory()

        # Set up the server side protocol
        channel = _PushHTTPChannel(self.reactor)
        channel.requestFactory = request_factory
        channel.site = self.site

        # Connect client to server and vice versa.
        client_to_server_transport = FakeTransport(
            channel, self.reactor, client_protocol
        )
        client_protocol.makeConnection(client_to_server_transport)

        server_to_client_transport = FakeTransport(
            client_protocol, self.reactor, channel
        )
        channel.makeConnection(server_to_client_transport)

        # The request will now be processed by `self.site` and the response
        # streamed back.
        self.reactor.advance(0)

        # We tear down the connection so it doesn't get reused without our
        # knowledge.
        server_to_client_transport.loseConnection()
        client_to_server_transport.loseConnection()

        return request_factory.request

    def assert_request_is_get_repl_stream_updates(
        self, request: SynapseRequest, stream_name: str
    ):
        """Asserts that the given request is a HTTP replication request for
        fetching updates for given stream.
        """

        self.assertRegex(
            request.path,
            br"^/_synapse/replication/get_repl_stream_updates/%s/[^/]+$"
            % (stream_name.encode("ascii"),),
        )

        self.assertEqual(request.method, b"GET")


class BaseMultiWorkerStreamTestCase(unittest.HomeserverTestCase):
    """Base class for tests running multiple workers.

    Automatically handle HTTP replication requests from workers to master,
    unlike `BaseStreamTestCase`.
    """

    servlets = []  # type: List[Callable[[HomeServer, JsonResource], None]]

    def setUp(self):
        super().setUp()

        # build a replication server
        self.server_factory = ReplicationStreamProtocolFactory(self.hs)
        self.streamer = self.hs.get_replication_streamer()

        store = self.hs.get_datastore()
        self.database_pool = store.db_pool

        self.reactor.lookups["testserv"] = "1.2.3.4"

        self._worker_hs_to_resource = {}

        # When we see a connection attempt to the master replication listener we
        # automatically set up the connection. This is so that tests don't
        # manually have to go and explicitly set it up each time (plus sometimes
        # it is impossible to write the handling explicitly in the tests).
        self.reactor.add_tcp_client_callback(
            "1.2.3.4", 8765, self._handle_http_replication_attempt
        )

    def create_test_json_resource(self):
        """Overrides `HomeserverTestCase.create_test_json_resource`.
        """
        # We override this so that it automatically registers all the HTTP
        # replication servlets, without having to explicitly do that in all
        # subclassses.

        resource = ReplicationRestResource(self.hs)

        for servlet in self.servlets:
            servlet(self.hs, resource)

        return resource

    def make_worker_hs(
        self, worker_app: str, extra_config: dict = {}, **kwargs
    ) -> HomeServer:
        """Make a new worker HS instance, correctly connecting replcation
        stream to the master HS.

        Args:
            worker_app: Type of worker, e.g. `synapse.app.federation_sender`.
            extra_config: Any extra config to use for this instances.
            **kwargs: Options that get passed to `self.setup_test_homeserver`,
                useful to e.g. pass some mocks for things like `http_client`

        Returns:
            The new worker HomeServer instance.
        """

        config = self._get_worker_hs_config()
        config["worker_app"] = worker_app
        config.update(extra_config)

        worker_hs = self.setup_test_homeserver(
            homeserverToUse=GenericWorkerServer,
            config=config,
            reactor=self.reactor,
            **kwargs
        )

        store = worker_hs.get_datastore()
        store.db_pool._db_pool = self.database_pool._db_pool

        repl_handler = ReplicationCommandHandler(worker_hs)
        client = ClientReplicationStreamProtocol(
            worker_hs, "client", "test", self.clock, repl_handler,
        )
        server = self.server_factory.buildProtocol(None)

        client_transport = FakeTransport(server, self.reactor)
        client.makeConnection(client_transport)

        server_transport = FakeTransport(client, self.reactor)
        server.makeConnection(server_transport)

        # Set up a resource for the worker
        resource = ReplicationRestResource(self.hs)

        for servlet in self.servlets:
            servlet(worker_hs, resource)

        self._worker_hs_to_resource[worker_hs] = resource

        return worker_hs

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"
        return config

    def render_on_worker(self, worker_hs: HomeServer, request: SynapseRequest):
        render(request, self._worker_hs_to_resource[worker_hs], self.reactor)

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump()

    def _handle_http_replication_attempt(self):
        """Handles a connection attempt to the master replication HTTP
        listener.
        """

        # We should have at least one outbound connection attempt, where the
        # last is one to the HTTP repication IP/port.
        clients = self.reactor.tcpClients
        self.assertGreaterEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients.pop()
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8765)

        # Set up client side protocol
        client_protocol = client_factory.buildProtocol(None)

        request_factory = OneShotRequestFactory()

        # Set up the server side protocol
        channel = _PushHTTPChannel(self.reactor)
        channel.requestFactory = request_factory
        channel.site = self.site

        # Connect client to server and vice versa.
        client_to_server_transport = FakeTransport(
            channel, self.reactor, client_protocol
        )
        client_protocol.makeConnection(client_to_server_transport)

        server_to_client_transport = FakeTransport(
            client_protocol, self.reactor, channel
        )
        channel.makeConnection(server_to_client_transport)

        # Note: at this point we've wired everything up, but we need to return
        # before the data starts flowing over the connections as this is called
        # inside `connecTCP` before the connection has been passed back to the
        # code that requested the TCP connection.


class TestReplicationDataHandler(GenericWorkerReplicationHandler):
    """Drop-in for ReplicationDataHandler which just collects RDATA rows"""

    def __init__(self, hs: HomeServer):
        super().__init__(hs)

        # list of received (stream_name, token, row) tuples
        self.received_rdata_rows = []  # type: List[Tuple[str, int, Any]]

    async def on_rdata(self, stream_name, instance_name, token, rows):
        await super().on_rdata(stream_name, instance_name, token, rows)
        for r in rows:
            self.received_rdata_rows.append((stream_name, token, r))


@attr.s()
class OneShotRequestFactory:
    """A simple request factory that generates a single `SynapseRequest` and
    stores it for future use. Can only be used once.
    """

    request = attr.ib(default=None)

    def __call__(self, *args, **kwargs):
        assert self.request is None

        self.request = SynapseRequest(*args, **kwargs)
        return self.request


class _PushHTTPChannel(HTTPChannel):
    """A HTTPChannel that wraps pull producers to push producers.

    This is a hack to get around the fact that HTTPChannel transparently wraps a
    pull producer (which is what Synapse uses to reply to requests) with
    `_PullToPush` to convert it to a push producer. Unfortunately `_PullToPush`
    uses the standard reactor rather than letting us use our test reactor, which
    makes it very hard to test.
    """

    def __init__(self, reactor: IReactorTime):
        super().__init__()
        self.reactor = reactor

        self._pull_to_push_producer = None  # type: Optional[_PullToPushProducer]

    def registerProducer(self, producer, streaming):
        # Convert pull producers to push producer.
        if not streaming:
            self._pull_to_push_producer = _PullToPushProducer(
                self.reactor, producer, self
            )
            producer = self._pull_to_push_producer

        super().registerProducer(producer, True)

    def unregisterProducer(self):
        if self._pull_to_push_producer:
            # We need to manually stop the _PullToPushProducer.
            self._pull_to_push_producer.stop()

    def checkPersistence(self, request, version):
        """Check whether the connection can be re-used
        """
        # We hijack this to always say no for ease of wiring stuff up in
        # `handle_http_replication_attempt`.
        request.responseHeaders.setRawHeaders(b"connection", [b"close"])
        return False


class _PullToPushProducer:
    """A push producer that wraps a pull producer.
    """

    def __init__(
        self, reactor: IReactorTime, producer: IPullProducer, consumer: IConsumer
    ):
        self._clock = Clock(reactor)
        self._producer = producer
        self._consumer = consumer

        # While running we use a looping call with a zero delay to call
        # resumeProducing on given producer.
        self._looping_call = None  # type: Optional[LoopingCall]

        # We start writing next reactor tick.
        self._start_loop()

    def _start_loop(self):
        """Start the looping call to
        """

        if not self._looping_call:
            # Start a looping call which runs every tick.
            self._looping_call = self._clock.looping_call(self._run_once, 0)

    def stop(self):
        """Stops calling resumeProducing.
        """
        if self._looping_call:
            self._looping_call.stop()
            self._looping_call = None

    def pauseProducing(self):
        """Implements IPushProducer
        """
        self.stop()

    def resumeProducing(self):
        """Implements IPushProducer
        """
        self._start_loop()

    def stopProducing(self):
        """Implements IPushProducer
        """
        self.stop()
        self._producer.stopProducing()

    def _run_once(self):
        """Calls resumeProducing on producer once.
        """

        try:
            self._producer.resumeProducing()
        except Exception:
            logger.exception("Failed to call resumeProducing")
            try:
                self._consumer.unregisterProducer()
            except Exception:
                pass

            self.stopProducing()
