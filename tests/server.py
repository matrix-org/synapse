# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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
import hashlib
import json
import logging
import os
import os.path
import time
import uuid
import warnings
from collections import deque
from io import SEEK_END, BytesIO
from typing import (
    Callable,
    Dict,
    Iterable,
    List,
    MutableMapping,
    Optional,
    Tuple,
    Type,
    Union,
)
from unittest.mock import Mock

import attr
from typing_extensions import Deque
from zope.interface import implementer

from twisted.internet import address, threads, udp
from twisted.internet._resolver import SimpleResolverComplexifier
from twisted.internet.defer import Deferred, fail, maybeDeferred, succeed
from twisted.internet.error import DNSLookupError
from twisted.internet.interfaces import (
    IAddress,
    IConsumer,
    IHostnameResolver,
    IProtocol,
    IPullProducer,
    IPushProducer,
    IReactorPluggableNameResolver,
    IReactorTime,
    IResolverSimple,
    ITransport,
)
from twisted.python.failure import Failure
from twisted.test.proto_helpers import AccumulatingProtocol, MemoryReactorClock
from twisted.web.http_headers import Headers
from twisted.web.resource import IResource
from twisted.web.server import Request, Site

from synapse.config.database import DatabaseConnectionConfig
from synapse.events.presence_router import load_legacy_presence_router
from synapse.events.spamcheck import load_legacy_spam_checkers
from synapse.events.third_party_rules import load_legacy_third_party_event_rules
from synapse.handlers.auth import load_legacy_password_auth_providers
from synapse.http.site import SynapseRequest
from synapse.logging.context import ContextResourceUsage
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.storage.engines import PostgresEngine, create_engine
from synapse.types import JsonDict
from synapse.util import Clock

from tests.utils import (
    LEAVE_DB,
    POSTGRES_BASE_DB,
    POSTGRES_HOST,
    POSTGRES_PASSWORD,
    POSTGRES_PORT,
    POSTGRES_USER,
    SQLITE_PERSIST_DB,
    USE_POSTGRES_FOR_TESTS,
    MockClock,
    default_config,
)

logger = logging.getLogger(__name__)

# the type of thing that can be passed into `make_request` in the headers list
CustomHeaderType = Tuple[Union[str, bytes], Union[str, bytes]]


class TimedOutException(Exception):
    """
    A web query timed out.
    """


@implementer(IConsumer)
@attr.s(auto_attribs=True)
class FakeChannel:
    """
    A fake Twisted Web Channel (the part that interfaces with the
    wire).
    """

    site: Union[Site, "FakeSite"]
    _reactor: MemoryReactorClock
    result: dict = attr.Factory(dict)
    _ip: str = "127.0.0.1"
    _producer: Optional[Union[IPullProducer, IPushProducer]] = None
    resource_usage: Optional[ContextResourceUsage] = None
    _request: Optional[Request] = None

    @property
    def request(self) -> Request:
        assert self._request is not None
        return self._request

    @request.setter
    def request(self, request: Request) -> None:
        assert self._request is None
        self._request = request

    @property
    def json_body(self) -> JsonDict:
        body = json.loads(self.text_body)
        assert isinstance(body, dict)
        return body

    @property
    def json_list(self) -> List[JsonDict]:
        body = json.loads(self.text_body)
        assert isinstance(body, list)
        return body

    @property
    def text_body(self) -> str:
        """The body of the result, utf-8-decoded.

        Raises an exception if the request has not yet completed.
        """
        if not self.is_finished:
            raise Exception("Request not yet completed")
        return self.result["body"].decode("utf8")

    def is_finished(self) -> bool:
        """check if the response has been completely received"""
        return self.result.get("done", False)

    @property
    def code(self) -> int:
        if not self.result:
            raise Exception("No result yet.")
        return int(self.result["code"])

    @property
    def headers(self) -> Headers:
        if not self.result:
            raise Exception("No result yet.")
        h = Headers()
        for i in self.result["headers"]:
            h.addRawHeader(*i)
        return h

    def writeHeaders(self, version, code, reason, headers):
        self.result["version"] = version
        self.result["code"] = code
        self.result["reason"] = reason
        self.result["headers"] = headers

    def write(self, content: bytes) -> None:
        assert isinstance(content, bytes), "Should be bytes! " + repr(content)

        if "body" not in self.result:
            self.result["body"] = b""

        self.result["body"] += content

    # Type ignore: mypy doesn't like the fact that producer isn't an IProducer.
    def registerProducer(  # type: ignore[override]
        self,
        producer: Union[IPullProducer, IPushProducer],
        streaming: bool,
    ) -> None:
        self._producer = producer
        self.producerStreaming = streaming

        def _produce() -> None:
            if self._producer:
                self._producer.resumeProducing()
                self._reactor.callLater(0.1, _produce)

        if not streaming:
            self._reactor.callLater(0.0, _produce)

    def unregisterProducer(self) -> None:
        if self._producer is None:
            return

        self._producer = None

    def requestDone(self, _self: Request) -> None:
        self.result["done"] = True
        if isinstance(_self, SynapseRequest):
            assert _self.logcontext is not None
            self.resource_usage = _self.logcontext.get_resource_usage()

    def getPeer(self) -> IAddress:
        # We give an address so that getClientAddress/getClientIP returns a non null entry,
        # causing us to record the MAU
        return address.IPv4Address("TCP", self._ip, 3423)

    def getHost(self) -> IAddress:
        # this is called by Request.__init__ to configure Request.host.
        return address.IPv4Address("TCP", "127.0.0.1", 8888)

    def isSecure(self) -> bool:
        return False

    @property
    def transport(self) -> "FakeChannel":
        return self

    def await_result(self, timeout_ms: int = 1000) -> None:
        """
        Wait until the request is finished.
        """
        end_time = self._reactor.seconds() + timeout_ms / 1000.0
        self._reactor.run()

        while not self.is_finished():
            # If there's a producer, tell it to resume producing so we get content
            if self._producer:
                self._producer.resumeProducing()

            if self._reactor.seconds() > end_time:
                raise TimedOutException("Timed out waiting for request to finish.")

            self._reactor.advance(0.1)

    def extract_cookies(self, cookies: MutableMapping[str, str]) -> None:
        """Process the contents of any Set-Cookie headers in the response

        Any cookines found are added to the given dict
        """
        headers = self.headers.getRawHeaders("Set-Cookie")
        if not headers:
            return

        for h in headers:
            parts = h.split(";")
            k, v = parts[0].split("=", maxsplit=1)
            cookies[k] = v


class FakeSite:
    """
    A fake Twisted Web Site, with mocks of the extra things that
    Synapse adds.
    """

    server_version_string = b"1"
    site_tag = "test"
    access_logger = logging.getLogger("synapse.access.http.fake")

    def __init__(self, resource: IResource, reactor: IReactorTime):
        """

        Args:
            resource: the resource to be used for rendering all requests
        """
        self._resource = resource
        self.reactor = reactor

    def getResourceFor(self, request):
        return self._resource


def make_request(
    reactor,
    site: Union[Site, FakeSite],
    method: Union[bytes, str],
    path: Union[bytes, str],
    content: Union[bytes, str, JsonDict] = b"",
    access_token: Optional[str] = None,
    request: Type[Request] = SynapseRequest,
    shorthand: bool = True,
    federation_auth_origin: Optional[bytes] = None,
    content_is_form: bool = False,
    await_result: bool = True,
    custom_headers: Optional[Iterable[CustomHeaderType]] = None,
    client_ip: str = "127.0.0.1",
) -> FakeChannel:
    """
    Make a web request using the given method, path and content, and render it

    Returns the fake Channel object which records the response to the request.

    Args:
        reactor:
        site: The twisted Site to use to render the request
        method: The HTTP request method ("verb").
        path: The HTTP path, suitably URL encoded (e.g. escaped UTF-8 & spaces and such).
        content: The body of the request. JSON-encoded, if a str of bytes.
        access_token: The access token to add as authorization for the request.
        request: The request class to create.
        shorthand: Whether to try and be helpful and prefix the given URL
            with the usual REST API path, if it doesn't contain it.
        federation_auth_origin: if set to not-None, we will add a fake
            Authorization header pretenting to be the given server name.
        content_is_form: Whether the content is URL encoded form data. Adds the
            'Content-Type': 'application/x-www-form-urlencoded' header.
        await_result: whether to wait for the request to complete rendering. If true,
             will pump the reactor until the the renderer tells the channel the request
             is finished.
        custom_headers: (name, value) pairs to add as request headers
        client_ip: The IP to use as the requesting IP. Useful for testing
            ratelimiting.

    Returns:
        channel
    """
    if not isinstance(method, bytes):
        method = method.encode("ascii")

    if not isinstance(path, bytes):
        path = path.encode("ascii")

    # Decorate it to be the full path, if we're using shorthand
    if (
        shorthand
        and not path.startswith(b"/_matrix")
        and not path.startswith(b"/_synapse")
    ):
        if path.startswith(b"/"):
            path = path[1:]
        path = b"/_matrix/client/r0/" + path

    if not path.startswith(b"/"):
        path = b"/" + path

    if isinstance(content, dict):
        content = json.dumps(content).encode("utf8")
    if isinstance(content, str):
        content = content.encode("utf8")

    channel = FakeChannel(site, reactor, ip=client_ip)

    req = request(channel, site)
    channel.request = req

    req.content = BytesIO(content)
    # Twisted expects to be at the end of the content when parsing the request.
    req.content.seek(0, SEEK_END)

    if access_token:
        req.requestHeaders.addRawHeader(
            b"Authorization", b"Bearer " + access_token.encode("ascii")
        )

    if federation_auth_origin is not None:
        req.requestHeaders.addRawHeader(
            b"Authorization",
            b"X-Matrix origin=%s,key=,sig=" % (federation_auth_origin,),
        )

    if content:
        if content_is_form:
            req.requestHeaders.addRawHeader(
                b"Content-Type", b"application/x-www-form-urlencoded"
            )
        else:
            # Assume the body is JSON
            req.requestHeaders.addRawHeader(b"Content-Type", b"application/json")

    if custom_headers:
        for k, v in custom_headers:
            req.requestHeaders.addRawHeader(k, v)

    req.parseCookies()
    req.requestReceived(method, path, b"1.1")

    if await_result:
        channel.await_result()

    return channel


@implementer(IReactorPluggableNameResolver)
class ThreadedMemoryReactorClock(MemoryReactorClock):
    """
    A MemoryReactorClock that supports callFromThread.
    """

    def __init__(self):
        self.threadpool = ThreadPool(self)

        self._tcp_callbacks: Dict[Tuple[str, int], Callable] = {}
        self._udp = []
        self.lookups: Dict[str, str] = {}
        self._thread_callbacks: Deque[Callable[[], None]] = deque()

        lookups = self.lookups

        @implementer(IResolverSimple)
        class FakeResolver:
            def getHostByName(self, name, timeout=None):
                if name not in lookups:
                    return fail(DNSLookupError("OH NO: unknown %s" % (name,)))
                return succeed(lookups[name])

        self.nameResolver = SimpleResolverComplexifier(FakeResolver())
        super().__init__()

    def installNameResolver(self, resolver: IHostnameResolver) -> IHostnameResolver:
        raise NotImplementedError()

    def listenUDP(self, port, protocol, interface="", maxPacketSize=8196):
        p = udp.Port(port, protocol, interface, maxPacketSize, self)
        p.startListening()
        self._udp.append(p)
        return p

    def callFromThread(self, callback, *args, **kwargs):
        """
        Make the callback fire in the next reactor iteration.
        """
        cb = lambda: callback(*args, **kwargs)
        # it's not safe to call callLater() here, so we append the callback to a
        # separate queue.
        self._thread_callbacks.append(cb)

    def getThreadPool(self):
        return self.threadpool

    def add_tcp_client_callback(self, host: str, port: int, callback: Callable):
        """Add a callback that will be invoked when we receive a connection
        attempt to the given IP/port using `connectTCP`.

        Note that the callback gets run before we return the connection to the
        client, which means callbacks cannot block while waiting for writes.
        """
        self._tcp_callbacks[(host, port)] = callback

    def connectTCP(self, host: str, port: int, factory, timeout=30, bindAddress=None):
        """Fake L{IReactorTCP.connectTCP}."""

        conn = super().connectTCP(
            host, port, factory, timeout=timeout, bindAddress=None
        )

        callback = self._tcp_callbacks.get((host, port))
        if callback:
            callback()

        return conn

    def advance(self, amount):
        # first advance our reactor's time, and run any "callLater" callbacks that
        # makes ready
        super().advance(amount)

        # now run any "callFromThread" callbacks
        while True:
            try:
                callback = self._thread_callbacks.popleft()
            except IndexError:
                break
            callback()

            # check for more "callLater" callbacks added by the thread callback
            # This isn't required in a regular reactor, but it ends up meaning that
            # our database queries can complete in a single call to `advance` [1] which
            # simplifies tests.
            #
            # [1]: we replace the threadpool backing the db connection pool with a
            # mock ThreadPool which doesn't really use threads; but we still use
            # reactor.callFromThread to feed results back from the db functions to the
            # main thread.
            super().advance(0)


class ThreadPool:
    """
    Threadless thread pool.
    """

    def __init__(self, reactor):
        self._reactor = reactor

    def start(self):
        pass

    def stop(self):
        pass

    def callInThreadWithCallback(self, onResult, function, *args, **kwargs):
        def _(res):
            if isinstance(res, Failure):
                onResult(False, res)
            else:
                onResult(True, res)

        d = Deferred()
        d.addCallback(lambda x: function(*args, **kwargs))
        d.addBoth(_)
        self._reactor.callLater(0, d.callback, True)
        return d


def _make_test_homeserver_synchronous(server: HomeServer) -> None:
    """
    Make the given test homeserver's database interactions synchronous.
    """

    clock = server.get_clock()

    for database in server.get_datastores().databases:
        pool = database._db_pool

        def runWithConnection(func, *args, **kwargs):
            return threads.deferToThreadPool(
                pool._reactor,
                pool.threadpool,
                pool._runWithConnection,
                func,
                *args,
                **kwargs,
            )

        def runInteraction(interaction, *args, **kwargs):
            return threads.deferToThreadPool(
                pool._reactor,
                pool.threadpool,
                pool._runInteraction,
                interaction,
                *args,
                **kwargs,
            )

        pool.runWithConnection = runWithConnection
        pool.runInteraction = runInteraction
        # Replace the thread pool with a threadless 'thread' pool
        pool.threadpool = ThreadPool(clock._reactor)
        pool.running = True

    # We've just changed the Databases to run DB transactions on the same
    # thread, so we need to disable the dedicated thread behaviour.
    server.get_datastores().main.USE_DEDICATED_DB_THREADS_FOR_EVENT_FETCHING = False


def get_clock() -> Tuple[ThreadedMemoryReactorClock, Clock]:
    clock = ThreadedMemoryReactorClock()
    hs_clock = Clock(clock)
    return clock, hs_clock


@implementer(ITransport)
@attr.s(cmp=False)
class FakeTransport:
    """
    A twisted.internet.interfaces.ITransport implementation which sends all its data
    straight into an IProtocol object: it exists to connect two IProtocols together.

    To use it, instantiate it with the receiving IProtocol, and then pass it to the
    sending IProtocol's makeConnection method:

        server = HTTPChannel()
        client.makeConnection(FakeTransport(server, self.reactor))

    If you want bidirectional communication, you'll need two instances.
    """

    other = attr.ib()
    """The Protocol object which will receive any data written to this transport.

    :type: twisted.internet.interfaces.IProtocol
    """

    _reactor = attr.ib()
    """Test reactor

    :type: twisted.internet.interfaces.IReactorTime
    """

    _protocol = attr.ib(default=None)
    """The Protocol which is producing data for this transport. Optional, but if set
    will get called back for connectionLost() notifications etc.
    """

    _peer_address: Optional[IAddress] = attr.ib(default=None)
    """The value to be returned by getPeer"""

    _host_address: Optional[IAddress] = attr.ib(default=None)
    """The value to be returned by getHost"""

    disconnecting = False
    disconnected = False
    connected = True
    buffer = attr.ib(default=b"")
    producer = attr.ib(default=None)
    autoflush = attr.ib(default=True)

    def getPeer(self) -> Optional[IAddress]:
        return self._peer_address

    def getHost(self) -> Optional[IAddress]:
        return self._host_address

    def loseConnection(self, reason=None):
        if not self.disconnecting:
            logger.info("FakeTransport: loseConnection(%s)", reason)
            self.disconnecting = True
            if self._protocol:
                self._protocol.connectionLost(reason)

            # if we still have data to write, delay until that is done
            if self.buffer:
                logger.info(
                    "FakeTransport: Delaying disconnect until buffer is flushed"
                )
            else:
                self.connected = False
                self.disconnected = True

    def abortConnection(self):
        logger.info("FakeTransport: abortConnection()")

        if not self.disconnecting:
            self.disconnecting = True
            if self._protocol:
                self._protocol.connectionLost(None)

        self.disconnected = True

    def pauseProducing(self):
        if not self.producer:
            return

        self.producer.pauseProducing()

    def resumeProducing(self):
        if not self.producer:
            return
        self.producer.resumeProducing()

    def unregisterProducer(self):
        if not self.producer:
            return

        self.producer = None

    def registerProducer(self, producer, streaming):
        self.producer = producer
        self.producerStreaming = streaming

        def _produce():
            if not self.producer:
                # we've been unregistered
                return
            # some implementations of IProducer (for example, FileSender)
            # don't return a deferred.
            d = maybeDeferred(self.producer.resumeProducing)
            d.addCallback(lambda x: self._reactor.callLater(0.1, _produce))

        if not streaming:
            self._reactor.callLater(0.0, _produce)

    def write(self, byt):
        if self.disconnecting:
            raise Exception("Writing to disconnecting FakeTransport")

        self.buffer = self.buffer + byt

        # always actually do the write asynchronously. Some protocols (notably the
        # TLSMemoryBIOProtocol) get very confused if a read comes back while they are
        # still doing a write. Doing a callLater here breaks the cycle.
        if self.autoflush:
            self._reactor.callLater(0.0, self.flush)

    def writeSequence(self, seq):
        for x in seq:
            self.write(x)

    def flush(self, maxbytes=None):
        if not self.buffer:
            # nothing to do. Don't write empty buffers: it upsets the
            # TLSMemoryBIOProtocol
            return

        if self.disconnected:
            return

        if maxbytes is not None:
            to_write = self.buffer[:maxbytes]
        else:
            to_write = self.buffer

        logger.info("%s->%s: %s", self._protocol, self.other, to_write)

        try:
            self.other.dataReceived(to_write)
        except Exception as e:
            logger.exception("Exception writing to protocol: %s", e)
            return

        self.buffer = self.buffer[len(to_write) :]
        if self.buffer and self.autoflush:
            self._reactor.callLater(0.0, self.flush)

        if not self.buffer and self.disconnecting:
            logger.info("FakeTransport: Buffer now empty, completing disconnect")
            self.disconnected = True


def connect_client(
    reactor: ThreadedMemoryReactorClock, client_id: int
) -> Tuple[IProtocol, AccumulatingProtocol]:
    """
    Connect a client to a fake TCP transport.

    Args:
        reactor
        factory: The connecting factory to build.
    """
    factory = reactor.tcpClients.pop(client_id)[2]
    client = factory.buildProtocol(None)
    server = AccumulatingProtocol()
    server.makeConnection(FakeTransport(client, reactor))
    client.makeConnection(FakeTransport(server, reactor))

    return client, server


class TestHomeServer(HomeServer):
    DATASTORE_CLASS = DataStore


def setup_test_homeserver(
    cleanup_func,
    name="test",
    config=None,
    reactor=None,
    homeserver_to_use: Type[HomeServer] = TestHomeServer,
    **kwargs,
):
    """
    Setup a homeserver suitable for running tests against.  Keyword arguments
    are passed to the Homeserver constructor.

    If no datastore is supplied, one is created and given to the homeserver.

    Args:
        cleanup_func : The function used to register a cleanup routine for
                       after the test.

    Calling this method directly is deprecated: you should instead derive from
    HomeserverTestCase.
    """
    if reactor is None:
        from twisted.internet import reactor

    if config is None:
        config = default_config(name, parse=True)

    config.caches.resize_all_caches()
    config.ldap_enabled = False

    if "clock" not in kwargs:
        kwargs["clock"] = MockClock()

    if USE_POSTGRES_FOR_TESTS:
        test_db = "synapse_test_%s" % uuid.uuid4().hex

        database_config = {
            "name": "psycopg2",
            "args": {
                "database": test_db,
                "host": POSTGRES_HOST,
                "password": POSTGRES_PASSWORD,
                "user": POSTGRES_USER,
                "port": POSTGRES_PORT,
                "cp_min": 1,
                "cp_max": 5,
            },
        }
    else:
        if SQLITE_PERSIST_DB:
            # The current working directory is in _trial_temp, so this gets created within that directory.
            test_db_location = os.path.abspath("test.db")
            logger.debug("Will persist db to %s", test_db_location)
            # Ensure each test gets a clean database.
            try:
                os.remove(test_db_location)
            except FileNotFoundError:
                pass
            else:
                logger.debug("Removed existing DB at %s", test_db_location)
        else:
            test_db_location = ":memory:"

        database_config = {
            "name": "sqlite3",
            "args": {"database": test_db_location, "cp_min": 1, "cp_max": 1},
        }

    if "db_txn_limit" in kwargs:
        database_config["txn_limit"] = kwargs["db_txn_limit"]

    database = DatabaseConnectionConfig("master", database_config)
    config.database.databases = [database]

    db_engine = create_engine(database.config)

    # Create the database before we actually try and connect to it, based off
    # the template database we generate in setupdb()
    if isinstance(db_engine, PostgresEngine):
        db_conn = db_engine.module.connect(
            database=POSTGRES_BASE_DB,
            user=POSTGRES_USER,
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            password=POSTGRES_PASSWORD,
        )
        db_conn.autocommit = True
        cur = db_conn.cursor()
        cur.execute("DROP DATABASE IF EXISTS %s;" % (test_db,))
        cur.execute(
            "CREATE DATABASE %s WITH TEMPLATE %s;" % (test_db, POSTGRES_BASE_DB)
        )
        cur.close()
        db_conn.close()

    hs = homeserver_to_use(
        name,
        config=config,
        version_string="Synapse/tests",
        reactor=reactor,
    )

    # Install @cache_in_self attributes
    for key, val in kwargs.items():
        setattr(hs, "_" + key, val)

    # Mock TLS
    hs.tls_server_context_factory = Mock()

    hs.setup()
    if homeserver_to_use == TestHomeServer:
        hs.setup_background_tasks()

    if isinstance(db_engine, PostgresEngine):
        database = hs.get_datastores().databases[0]

        # We need to do cleanup on PostgreSQL
        def cleanup():
            import psycopg2

            # Close all the db pools
            database._db_pool.close()

            dropped = False

            # Drop the test database
            db_conn = db_engine.module.connect(
                database=POSTGRES_BASE_DB,
                user=POSTGRES_USER,
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                password=POSTGRES_PASSWORD,
            )
            db_conn.autocommit = True
            cur = db_conn.cursor()

            # Try a few times to drop the DB. Some things may hold on to the
            # database for a few more seconds due to flakiness, preventing
            # us from dropping it when the test is over. If we can't drop
            # it, warn and move on.
            for _ in range(5):
                try:
                    cur.execute("DROP DATABASE IF EXISTS %s;" % (test_db,))
                    db_conn.commit()
                    dropped = True
                except psycopg2.OperationalError as e:
                    warnings.warn(
                        "Couldn't drop old db: " + str(e), category=UserWarning
                    )
                    time.sleep(0.5)

            cur.close()
            db_conn.close()

            if not dropped:
                warnings.warn("Failed to drop old DB.", category=UserWarning)

        if not LEAVE_DB:
            # Register the cleanup hook
            cleanup_func(cleanup)

    # bcrypt is far too slow to be doing in unit tests
    # Need to let the HS build an auth handler and then mess with it
    # because AuthHandler's constructor requires the HS, so we can't make one
    # beforehand and pass it in to the HS's constructor (chicken / egg)
    async def hash(p):
        return hashlib.md5(p.encode("utf8")).hexdigest()

    hs.get_auth_handler().hash = hash

    async def validate_hash(p, h):
        return hashlib.md5(p.encode("utf8")).hexdigest() == h

    hs.get_auth_handler().validate_hash = validate_hash

    # Make the threadpool and database transactions synchronous for testing.
    _make_test_homeserver_synchronous(hs)

    # Load any configured modules into the homeserver
    module_api = hs.get_module_api()
    for module, config in hs.config.modules.loaded_modules:
        module(config=config, api=module_api)

    load_legacy_spam_checkers(hs)
    load_legacy_third_party_event_rules(hs)
    load_legacy_presence_router(hs)
    load_legacy_password_auth_providers(hs)

    return hs
