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
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from twisted.internet.interfaces import IConsumer, IPullProducer, IReactorTime
from twisted.internet.protocol import Protocol
from twisted.internet.task import LoopingCall
from twisted.web.http import HTTPChannel
from twisted.web.resource import Resource
from twisted.web.server import Request, Site

from synapse.app.generic_worker import (
    GenericWorkerReplicationHandler,
    GenericWorkerServer,
)
from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest, SynapseSite
from synapse.replication.http import ReplicationRestResource
from synapse.replication.tcp.handler import ReplicationCommandHandler
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol
from synapse.replication.tcp.resource import (
    ReplicationStreamProtocolFactory,
    ServerReplicationStreamProtocol,
)
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.server import FakeTransport

try:
    import hiredis
except ImportError:
    hiredis = None  # type: ignore

logger = logging.getLogger(__name__)


class BaseStreamTestCase(unittest.HomeserverTestCase):
    """Base class for tests of the replication streams"""

    # hiredis is an optional dependency so we don't want to require it for running
    # the tests.
    if not hiredis:
        skip = "Requires hiredis"

    def prepare(self, reactor, clock, hs):
        # build a replication server
        server_factory = ReplicationStreamProtocolFactory(hs)
        self.streamer = hs.get_replication_streamer()
        self.server = server_factory.buildProtocol(
            None
        )  # type: ServerReplicationStreamProtocol

        # Make a new HomeServer object for the worker
        self.reactor.lookups["testserv"] = "1.2.3.4"
        self.worker_hs = self.setup_test_homeserver(
            federation_http_client=None,
            homeserver_to_use=GenericWorkerServer,
            config=self._get_worker_hs_config(),
            reactor=self.reactor,
        )

        # Since we use sqlite in memory databases we need to make sure the
        # databases objects are the same.
        self.worker_hs.get_datastore().db_pool = hs.get_datastore().db_pool

        self.test_handler = self._build_replication_data_handler()
        self.worker_hs._replication_data_handler = self.test_handler

        repl_handler = ReplicationCommandHandler(self.worker_hs)
        self.client = ClientReplicationStreamProtocol(
            self.worker_hs,
            "client",
            "test",
            clock,
            repl_handler,
        )

        self._client_transport = None
        self._server_transport = None

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d["/_synapse/replication"] = ReplicationRestResource(self.hs)
        return d

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

        # Set up the server side protocol
        channel = _PushHTTPChannel(self.reactor, SynapseRequest, self.site)

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

        return channel.request

    def assert_request_is_get_repl_stream_updates(
        self, request: SynapseRequest, stream_name: str
    ):
        """Asserts that the given request is a HTTP replication request for
        fetching updates for given stream.
        """

        path = request.path  # type: bytes  # type: ignore
        self.assertRegex(
            path,
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

        # Fake in memory Redis server that servers can connect to.
        self._redis_server = FakeRedisPubSubServer()

        # We may have an attempt to connect to redis for the external cache already.
        self.connect_any_redis_attempts()

        store = self.hs.get_datastore()
        self.database_pool = store.db_pool

        self.reactor.lookups["testserv"] = "1.2.3.4"
        self.reactor.lookups["localhost"] = "127.0.0.1"

        # A map from a HS instance to the associated HTTP Site to use for
        # handling inbound HTTP requests to that instance.
        self._hs_to_site = {self.hs: self.site}

        if self.hs.config.redis.redis_enabled:
            # Handle attempts to connect to fake redis server.
            self.reactor.add_tcp_client_callback(
                b"localhost",
                6379,
                self.connect_any_redis_attempts,
            )

            self.hs.get_tcp_replication().start_replication(self.hs)

        # When we see a connection attempt to the master replication listener we
        # automatically set up the connection. This is so that tests don't
        # manually have to go and explicitly set it up each time (plus sometimes
        # it is impossible to write the handling explicitly in the tests).
        #
        # Register the master replication listener:
        self.reactor.add_tcp_client_callback(
            "1.2.3.4",
            8765,
            lambda: self._handle_http_replication_attempt(self.hs, 8765),
        )

    def create_test_resource(self):
        """Overrides `HomeserverTestCase.create_test_resource`."""
        # We override this so that it automatically registers all the HTTP
        # replication servlets, without having to explicitly do that in all
        # subclassses.

        resource = ReplicationRestResource(self.hs)

        for servlet in self.servlets:
            servlet(self.hs, resource)

        return resource

    def make_worker_hs(
        self, worker_app: str, extra_config: Optional[dict] = None, **kwargs
    ) -> HomeServer:
        """Make a new worker HS instance, correctly connecting replcation
        stream to the master HS.

        Args:
            worker_app: Type of worker, e.g. `synapse.app.federation_sender`.
            extra_config: Any extra config to use for this instances.
            **kwargs: Options that get passed to `self.setup_test_homeserver`,
                useful to e.g. pass some mocks for things like `federation_http_client`

        Returns:
            The new worker HomeServer instance.
        """

        config = self._get_worker_hs_config()
        config["worker_app"] = worker_app
        config.update(extra_config or {})

        worker_hs = self.setup_test_homeserver(
            homeserver_to_use=GenericWorkerServer,
            config=config,
            reactor=self.reactor,
            **kwargs,
        )

        # If the instance is in the `instance_map` config then workers may try
        # and send HTTP requests to it, so we register it with
        # `_handle_http_replication_attempt` like we do with the master HS.
        instance_name = worker_hs.get_instance_name()
        instance_loc = worker_hs.config.worker.instance_map.get(instance_name)
        if instance_loc:
            # Ensure the host is one that has a fake DNS entry.
            if instance_loc.host not in self.reactor.lookups:
                raise Exception(
                    "Host does not have an IP for instance_map[%r].host = %r"
                    % (
                        instance_name,
                        instance_loc.host,
                    )
                )

            self.reactor.add_tcp_client_callback(
                self.reactor.lookups[instance_loc.host],
                instance_loc.port,
                lambda: self._handle_http_replication_attempt(
                    worker_hs, instance_loc.port
                ),
            )

        store = worker_hs.get_datastore()
        store.db_pool._db_pool = self.database_pool._db_pool

        # Set up TCP replication between master and the new worker if we don't
        # have Redis support enabled.
        if not worker_hs.config.redis_enabled:
            repl_handler = ReplicationCommandHandler(worker_hs)
            client = ClientReplicationStreamProtocol(
                worker_hs,
                "client",
                "test",
                self.clock,
                repl_handler,
            )
            server = self.server_factory.buildProtocol(None)

            client_transport = FakeTransport(server, self.reactor)
            client.makeConnection(client_transport)

            server_transport = FakeTransport(client, self.reactor)
            server.makeConnection(server_transport)

        # Set up a resource for the worker
        resource = ReplicationRestResource(worker_hs)

        for servlet in self.servlets:
            servlet(worker_hs, resource)

        self._hs_to_site[worker_hs] = SynapseSite(
            logger_name="synapse.access.http.fake",
            site_tag="{}-{}".format(
                worker_hs.config.server.server_name, worker_hs.get_instance_name()
            ),
            config=worker_hs.config.server.listeners[0],
            resource=resource,
            server_version_string="1",
        )

        if worker_hs.config.redis.redis_enabled:
            worker_hs.get_tcp_replication().start_replication(worker_hs)

        return worker_hs

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"
        return config

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump()

    def _handle_http_replication_attempt(self, hs, repl_port):
        """Handles a connection attempt to the given HS replication HTTP
        listener on the given port.
        """

        # We should have at least one outbound connection attempt, where the
        # last is one to the HTTP repication IP/port.
        clients = self.reactor.tcpClients
        self.assertGreaterEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients.pop()
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, repl_port)

        # Set up client side protocol
        client_protocol = client_factory.buildProtocol(None)

        # Set up the server side protocol
        channel = _PushHTTPChannel(self.reactor, SynapseRequest, self._hs_to_site[hs])

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

    def connect_any_redis_attempts(self):
        """If redis is enabled we need to deal with workers connecting to a
        redis server. We don't want to use a real Redis server so we use a
        fake one.
        """
        clients = self.reactor.tcpClients
        while clients:
            (host, port, client_factory, _timeout, _bindAddress) = clients.pop(0)
            self.assertEqual(host, b"localhost")
            self.assertEqual(port, 6379)

            client_protocol = client_factory.buildProtocol(None)
            server_protocol = self._redis_server.buildProtocol(None)

            client_to_server_transport = FakeTransport(
                server_protocol, self.reactor, client_protocol
            )
            client_protocol.makeConnection(client_to_server_transport)

            server_to_client_transport = FakeTransport(
                client_protocol, self.reactor, server_protocol
            )
            server_protocol.makeConnection(server_to_client_transport)


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


class _PushHTTPChannel(HTTPChannel):
    """A HTTPChannel that wraps pull producers to push producers.

    This is a hack to get around the fact that HTTPChannel transparently wraps a
    pull producer (which is what Synapse uses to reply to requests) with
    `_PullToPush` to convert it to a push producer. Unfortunately `_PullToPush`
    uses the standard reactor rather than letting us use our test reactor, which
    makes it very hard to test.
    """

    def __init__(
        self, reactor: IReactorTime, request_factory: Type[Request], site: Site
    ):
        super().__init__()
        self.reactor = reactor
        self.requestFactory = request_factory
        self.site = site

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
        """Check whether the connection can be re-used"""
        # We hijack this to always say no for ease of wiring stuff up in
        # `handle_http_replication_attempt`.
        request.responseHeaders.setRawHeaders(b"connection", [b"close"])
        return False

    def requestDone(self, request):
        # Store the request for inspection.
        self.request = request
        super().requestDone(request)


class _PullToPushProducer:
    """A push producer that wraps a pull producer."""

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
        """Start the looping call to"""

        if not self._looping_call:
            # Start a looping call which runs every tick.
            self._looping_call = self._clock.looping_call(self._run_once, 0)

    def stop(self):
        """Stops calling resumeProducing."""
        if self._looping_call:
            self._looping_call.stop()
            self._looping_call = None

    def pauseProducing(self):
        """Implements IPushProducer"""
        self.stop()

    def resumeProducing(self):
        """Implements IPushProducer"""
        self._start_loop()

    def stopProducing(self):
        """Implements IPushProducer"""
        self.stop()
        self._producer.stopProducing()

    def _run_once(self):
        """Calls resumeProducing on producer once."""

        try:
            self._producer.resumeProducing()
        except Exception:
            logger.exception("Failed to call resumeProducing")
            try:
                self._consumer.unregisterProducer()
            except Exception:
                pass

            self.stopProducing()


class FakeRedisPubSubServer:
    """A fake Redis server for pub/sub."""

    def __init__(self):
        self._subscribers = set()

    def add_subscriber(self, conn):
        """A connection has called SUBSCRIBE"""
        self._subscribers.add(conn)

    def remove_subscriber(self, conn):
        """A connection has called UNSUBSCRIBE"""
        self._subscribers.discard(conn)

    def publish(self, conn, channel, msg) -> int:
        """A connection want to publish a message to subscribers."""
        for sub in self._subscribers:
            sub.send(["message", channel, msg])

        return len(self._subscribers)

    def buildProtocol(self, addr):
        return FakeRedisPubSubProtocol(self)


class FakeRedisPubSubProtocol(Protocol):
    """A connection from a client talking to the fake Redis server."""

    transport = None  # type: Optional[FakeTransport]

    def __init__(self, server: FakeRedisPubSubServer):
        self._server = server
        self._reader = hiredis.Reader()

    def dataReceived(self, data):
        self._reader.feed(data)

        # We might get multiple messages in one packet.
        while True:
            msg = self._reader.gets()

            if msg is False:
                # No more messages.
                return

            if not isinstance(msg, list):
                # Inbound commands should always be a list
                raise Exception("Expected redis list")

            self.handle_command(msg[0], *msg[1:])

    def handle_command(self, command, *args):
        """Received a Redis command from the client."""

        # We currently only support pub/sub.
        if command == b"PUBLISH":
            channel, message = args
            num_subscribers = self._server.publish(self, channel, message)
            self.send(num_subscribers)
        elif command == b"SUBSCRIBE":
            (channel,) = args
            self._server.add_subscriber(self)
            self.send(["subscribe", channel, 1])

        # Since we use SET/GET to cache things we can safely no-op them.
        elif command == b"SET":
            self.send("OK")
        elif command == b"GET":
            self.send(None)
        else:
            raise Exception("Unknown command")

    def send(self, msg):
        """Send a message back to the client."""
        assert self.transport is not None

        raw = self.encode(msg).encode("utf-8")

        self.transport.write(raw)
        self.transport.flush()

    def encode(self, obj):
        """Encode an object to its Redis format.

        Supports: strings/bytes, integers and list/tuples.
        """

        if isinstance(obj, bytes):
            # We assume bytes are just unicode strings.
            obj = obj.decode("utf-8")

        if obj is None:
            return "$-1\r\n"
        if isinstance(obj, str):
            return "${len}\r\n{str}\r\n".format(len=len(obj), str=obj)
        if isinstance(obj, int):
            return ":{val}\r\n".format(val=obj)
        if isinstance(obj, (list, tuple)):
            items = "".join(self.encode(a) for a in obj)
            return "*{len}\r\n{items}".format(len=len(obj), items=items)

        raise Exception("Unrecognized type for encoding redis: %r: %r", type(obj), obj)

    def connectionLost(self, reason):
        self._server.remove_subscriber(self)
