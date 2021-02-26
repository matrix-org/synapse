import json
import logging
from collections import deque
from io import SEEK_END, BytesIO
from typing import Callable, Iterable, MutableMapping, Optional, Tuple, Union

import attr
from typing_extensions import Deque
from zope.interface import implementer

from twisted.internet import address, threads, udp
from twisted.internet._resolver import SimpleResolverComplexifier
from twisted.internet.defer import Deferred, fail, succeed
from twisted.internet.error import DNSLookupError
from twisted.internet.interfaces import (
    IReactorPluggableNameResolver,
    IReactorTCP,
    IResolverSimple,
)
from twisted.python.failure import Failure
from twisted.test.proto_helpers import AccumulatingProtocol, MemoryReactorClock
from twisted.web.http_headers import Headers
from twisted.web.resource import IResource
from twisted.web.server import Site

from synapse.http.site import SynapseRequest
from synapse.util import Clock

from tests.utils import setup_test_homeserver as _sth

logger = logging.getLogger(__name__)


class TimedOutException(Exception):
    """
    A web query timed out.
    """


@attr.s
class FakeChannel:
    """
    A fake Twisted Web Channel (the part that interfaces with the
    wire).
    """

    site = attr.ib(type=Site)
    _reactor = attr.ib()
    result = attr.ib(type=dict, default=attr.Factory(dict))
    _ip = attr.ib(type=str, default="127.0.0.1")
    _producer = None

    @property
    def json_body(self):
        return json.loads(self.text_body)

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
    def code(self):
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

    def write(self, content):
        assert isinstance(content, bytes), "Should be bytes! " + repr(content)

        if "body" not in self.result:
            self.result["body"] = b""

        self.result["body"] += content

    def registerProducer(self, producer, streaming):
        self._producer = producer
        self.producerStreaming = streaming

        def _produce():
            if self._producer:
                self._producer.resumeProducing()
                self._reactor.callLater(0.1, _produce)

        if not streaming:
            self._reactor.callLater(0.0, _produce)

    def unregisterProducer(self):
        if self._producer is None:
            return

        self._producer = None

    def requestDone(self, _self):
        self.result["done"] = True

    def getPeer(self):
        # We give an address so that getClientIP returns a non null entry,
        # causing us to record the MAU
        return address.IPv4Address("TCP", self._ip, 3423)

    def getHost(self):
        return None

    @property
    def transport(self):
        return self

    def await_result(self, timeout: int = 100) -> None:
        """
        Wait until the request is finished.
        """
        self._reactor.run()
        x = 0

        while not self.is_finished():
            # If there's a producer, tell it to resume producing so we get content
            if self._producer:
                self._producer.resumeProducing()

            x += 1

            if x > timeout:
                raise TimedOutException("Timed out waiting for request to finish.")

            self._reactor.advance(0.1)

    def extract_cookies(self, cookies: MutableMapping[str, str]) -> None:
        """Process the contents of any Set-Cookie headers in the response

        Any cookines found are added to the given dict
        """
        for h in self.headers.getRawHeaders("Set-Cookie"):
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

    def __init__(self, resource: IResource):
        """

        Args:
            resource: the resource to be used for rendering all requests
        """
        self._resource = resource

    def getResourceFor(self, request):
        return self._resource


def make_request(
    reactor,
    site: Site,
    method,
    path,
    content=b"",
    access_token=None,
    request=SynapseRequest,
    shorthand=True,
    federation_auth_origin=None,
    content_is_form=False,
    await_result: bool = True,
    custom_headers: Optional[
        Iterable[Tuple[Union[bytes, str], Union[bytes, str]]]
    ] = None,
    client_ip: str = "127.0.0.1",
) -> FakeChannel:
    """
    Make a web request using the given method, path and content, and render it

    Returns the fake Channel object which records the response to the request.

    Args:
        site: The twisted Site to use to render the request

        method (bytes/unicode): The HTTP request method ("verb").
        path (bytes/unicode): The HTTP path, suitably URL encoded (e.g.
        escaped UTF-8 & spaces and such).
        content (bytes or dict): The body of the request. JSON-encoded, if
        a dict.
        shorthand: Whether to try and be helpful and prefix the given URL
        with the usual REST API path, if it doesn't contain it.
        federation_auth_origin (bytes|None): if set to not-None, we will add a fake
            Authorization header pretenting to be the given server name.
        content_is_form: Whether the content is URL encoded form data. Adds the
            'Content-Type': 'application/x-www-form-urlencoded' header.

        custom_headers: (name, value) pairs to add as request headers

        await_result: whether to wait for the request to complete rendering. If true,
             will pump the reactor until the the renderer tells the channel the request
             is finished.

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

    req = request(channel)
    req.content = BytesIO(content)
    # Twisted expects to be at the end of the content when parsing the request.
    req.content.seek(SEEK_END)

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

        self._tcp_callbacks = {}
        self._udp = []
        lookups = self.lookups = {}
        self._thread_callbacks = deque()  # type: Deque[Callable[[], None]]()

        @implementer(IResolverSimple)
        class FakeResolver:
            def getHostByName(self, name, timeout=None):
                if name not in lookups:
                    return fail(DNSLookupError("OH NO: unknown %s" % (name,)))
                return succeed(lookups[name])

        self.nameResolver = SimpleResolverComplexifier(FakeResolver())
        super().__init__()

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

    def add_tcp_client_callback(self, host, port, callback):
        """Add a callback that will be invoked when we receive a connection
        attempt to the given IP/port using `connectTCP`.

        Note that the callback gets run before we return the connection to the
        client, which means callbacks cannot block while waiting for writes.
        """
        self._tcp_callbacks[(host, port)] = callback

    def connectTCP(self, host, port, factory, timeout=30, bindAddress=None):
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


def setup_test_homeserver(cleanup_func, *args, **kwargs):
    """
    Set up a synchronous test server, driven by the reactor used by
    the homeserver.
    """
    server = _sth(cleanup_func, *args, **kwargs)

    # Make the thread pool synchronous.
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
        pool.threadpool = ThreadPool(clock._reactor)
        pool.running = True

    # We've just changed the Databases to run DB transactions on the same
    # thread, so we need to disable the dedicated thread behaviour.
    server.get_datastores().main.USE_DEDICATED_DB_THREADS_FOR_EVENT_FETCHING = False

    return server


def get_clock():
    clock = ThreadedMemoryReactorClock()
    hs_clock = Clock(clock)
    return clock, hs_clock


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

    disconnecting = False
    disconnected = False
    connected = True
    buffer = attr.ib(default=b"")
    producer = attr.ib(default=None)
    autoflush = attr.ib(default=True)

    def getPeer(self):
        return None

    def getHost(self):
        return None

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
            d = self.producer.resumeProducing()
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

        if getattr(self.other, "transport") is None:
            # the other has no transport yet; reschedule
            if self.autoflush:
                self._reactor.callLater(0.0, self.flush)
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


def connect_client(reactor: IReactorTCP, client_id: int) -> AccumulatingProtocol:
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
