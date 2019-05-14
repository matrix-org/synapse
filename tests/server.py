import json
import logging
from io import BytesIO

from six import text_type

import attr
from zope.interface import implementer

from twisted.internet import address, threads, udp
from twisted.internet._resolver import SimpleResolverComplexifier
from twisted.internet.defer import Deferred, fail, succeed
from twisted.internet.error import DNSLookupError
from twisted.internet.interfaces import IReactorPluggableNameResolver, IResolverSimple
from twisted.python.failure import Failure
from twisted.test.proto_helpers import MemoryReactorClock
from twisted.web.http import unquote
from twisted.web.http_headers import Headers

from synapse.http.site import SynapseRequest
from synapse.util import Clock

from tests.utils import setup_test_homeserver as _sth

logger = logging.getLogger(__name__)


class TimedOutException(Exception):
    """
    A web query timed out.
    """


@attr.s
class FakeChannel(object):
    """
    A fake Twisted Web Channel (the part that interfaces with the
    wire).
    """

    _reactor = attr.ib()
    result = attr.ib(default=attr.Factory(dict))
    _producer = None

    @property
    def json_body(self):
        if not self.result:
            raise Exception("No result yet.")
        return json.loads(self.result["body"].decode('utf8'))

    @property
    def code(self):
        if not self.result:
            raise Exception("No result yet.")
        return int(self.result["code"])

    @property
    def headers(self):
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
        return address.IPv4Address("TCP", "127.0.0.1", 3423)

    def getHost(self):
        return None

    @property
    def transport(self):
        return self


class FakeSite:
    """
    A fake Twisted Web Site, with mocks of the extra things that
    Synapse adds.
    """

    server_version_string = b"1"
    site_tag = "test"
    access_logger = logging.getLogger("synapse.access.http.fake")


def make_request(
    reactor,
    method,
    path,
    content=b"",
    access_token=None,
    request=SynapseRequest,
    shorthand=True,
    federation_auth_origin=None,
):
    """
    Make a web request using the given method and path, feed it the
    content, and return the Request and the Channel underneath.

    Args:
        method (bytes/unicode): The HTTP request method ("verb").
        path (bytes/unicode): The HTTP path, suitably URL encoded (e.g.
        escaped UTF-8 & spaces and such).
        content (bytes or dict): The body of the request. JSON-encoded, if
        a dict.
        shorthand: Whether to try and be helpful and prefix the given URL
        with the usual REST API path, if it doesn't contain it.
        federation_auth_origin (bytes|None): if set to not-None, we will add a fake
            Authorization header pretenting to be the given server name.

    Returns:
        Tuple[synapse.http.site.SynapseRequest, channel]
    """
    if not isinstance(method, bytes):
        method = method.encode('ascii')

    if not isinstance(path, bytes):
        path = path.encode('ascii')

    # Decorate it to be the full path, if we're using shorthand
    if shorthand and not path.startswith(b"/_matrix"):
        path = b"/_matrix/client/r0/" + path
        path = path.replace(b"//", b"/")

    if not path.startswith(b"/"):
        path = b"/" + path

    if isinstance(content, text_type):
        content = content.encode('utf8')

    site = FakeSite()
    channel = FakeChannel(reactor)

    req = request(site, channel)
    req.process = lambda: b""
    req.content = BytesIO(content)
    req.postpath = list(map(unquote, path[1:].split(b'/')))

    if access_token:
        req.requestHeaders.addRawHeader(
            b"Authorization", b"Bearer " + access_token.encode('ascii')
        )

    if federation_auth_origin is not None:
        req.requestHeaders.addRawHeader(
            b"Authorization",
            b"X-Matrix origin=%s,key=,sig=" % (federation_auth_origin,),
        )

    if content:
        req.requestHeaders.addRawHeader(b"Content-Type", b"application/json")

    req.requestReceived(method, path, b"1.1")

    return req, channel


def wait_until_result(clock, request, timeout=100):
    """
    Wait until the request is finished.
    """
    clock.run()
    x = 0

    while not request.finished:

        # If there's a producer, tell it to resume producing so we get content
        if request._channel._producer:
            request._channel._producer.resumeProducing()

        x += 1

        if x > timeout:
            raise TimedOutException("Timed out waiting for request to finish.")

        clock.advance(0.1)


def render(request, resource, clock):
    request.render(resource)
    wait_until_result(clock, request)


@implementer(IReactorPluggableNameResolver)
class ThreadedMemoryReactorClock(MemoryReactorClock):
    """
    A MemoryReactorClock that supports callFromThread.
    """

    def __init__(self):
        self._udp = []
        lookups = self.lookups = {}

        @implementer(IResolverSimple)
        class FakeResolver(object):
            def getHostByName(self, name, timeout=None):
                if name not in lookups:
                    return fail(DNSLookupError("OH NO: unknown %s" % (name,)))
                return succeed(lookups[name])

        self.nameResolver = SimpleResolverComplexifier(FakeResolver())
        super(ThreadedMemoryReactorClock, self).__init__()

    def listenUDP(self, port, protocol, interface='', maxPacketSize=8196):
        p = udp.Port(port, protocol, interface, maxPacketSize, self)
        p.startListening()
        self._udp.append(p)
        return p

    def callFromThread(self, callback, *args, **kwargs):
        """
        Make the callback fire in the next reactor iteration.
        """
        d = Deferred()
        d.addCallback(lambda x: callback(*args, **kwargs))
        self.callLater(0, d.callback, True)
        return d


def setup_test_homeserver(cleanup_func, *args, **kwargs):
    """
    Set up a synchronous test server, driven by the reactor used by
    the homeserver.
    """
    d = _sth(cleanup_func, *args, **kwargs).result

    if isinstance(d, Failure):
        d.raiseException()

    # Make the thread pool synchronous.
    clock = d.get_clock()
    pool = d.get_db_pool()

    def runWithConnection(func, *args, **kwargs):
        return threads.deferToThreadPool(
            pool._reactor,
            pool.threadpool,
            pool._runWithConnection,
            func,
            *args,
            **kwargs
        )

    def runInteraction(interaction, *args, **kwargs):
        return threads.deferToThreadPool(
            pool._reactor,
            pool.threadpool,
            pool._runInteraction,
            interaction,
            *args,
            **kwargs
        )

    class ThreadPool:
        """
        Threadless thread pool.
        """

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
            clock._reactor.callLater(0, d.callback, True)
            return d

    clock.threadpool = ThreadPool()

    if pool:
        pool.runWithConnection = runWithConnection
        pool.runInteraction = runInteraction
        pool.threadpool = ThreadPool()
        pool.running = True
    return d


def get_clock():
    clock = ThreadedMemoryReactorClock()
    hs_clock = Clock(clock)
    return (clock, hs_clock)


@attr.s(cmp=False)
class FakeTransport(object):
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
    buffer = attr.ib(default=b'')
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
            self.disconnected = True

    def abortConnection(self):
        logger.info("FakeTransport: abortConnection()")
        self.loseConnection()

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
            logger.warning("Exception writing to protocol: %s", e)
            return

        self.buffer = self.buffer[len(to_write) :]
        if self.buffer and self.autoflush:
            self._reactor.callLater(0.0, self.flush)
