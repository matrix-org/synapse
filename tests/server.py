import json
from io import BytesIO

from six import text_type

import attr
from zope.interface import implementer

from twisted.internet import address, threads, udp
from twisted.internet._resolver import HostResolution
from twisted.internet.address import IPv4Address
from twisted.internet.defer import Deferred
from twisted.internet.error import DNSLookupError
from twisted.internet.interfaces import IReactorPluggableNameResolver
from twisted.python.failure import Failure
from twisted.test.proto_helpers import MemoryReactorClock

from synapse.http.site import SynapseRequest
from synapse.util import Clock

from tests.utils import setup_test_homeserver as _sth


@attr.s
class FakeChannel(object):
    """
    A fake Twisted Web Channel (the part that interfaces with the
    wire).
    """

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

    def writeHeaders(self, version, code, reason, headers):
        self.result["version"] = version
        self.result["code"] = code
        self.result["reason"] = reason
        self.result["headers"] = headers

    def write(self, content):
        if "body" not in self.result:
            self.result["body"] = b""

        self.result["body"] += content

    def registerProducer(self, producer, streaming):
        self._producer = producer

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

    @property
    def access_logger(self):
        class FakeLogger:
            def info(self, *args, **kwargs):
                pass

        return FakeLogger()


def make_request(method, path, content=b"", access_token=None):
    """
    Make a web request using the given method and path, feed it the
    content, and return the Request and the Channel underneath.
    """
    if not isinstance(method, bytes):
        method = method.encode('ascii')

    if not isinstance(path, bytes):
        path = path.encode('ascii')

    # Decorate it to be the full path
    if not path.startswith(b"/_matrix"):
        path = b"/_matrix/client/r0/" + path
        path = path.replace(b"//", b"/")

    if isinstance(content, text_type):
        content = content.encode('utf8')

    site = FakeSite()
    channel = FakeChannel()

    req = SynapseRequest(site, channel)
    req.process = lambda: b""
    req.content = BytesIO(content)

    if access_token:
        req.requestHeaders.addRawHeader(b"Authorization", b"Bearer " + access_token)

    req.requestHeaders.addRawHeader(b"X-Forwarded-For", b"127.0.0.1")
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
            raise Exception("Timed out waiting for request to finish.")

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
        self.lookups = {}

        class Resolver(object):
            def resolveHostName(
                _self,
                resolutionReceiver,
                hostName,
                portNumber=0,
                addressTypes=None,
                transportSemantics='TCP',
            ):

                resolution = HostResolution(hostName)
                resolutionReceiver.resolutionBegan(resolution)
                if hostName not in self.lookups:
                    raise DNSLookupError("OH NO")

                resolutionReceiver.addressResolved(
                    IPv4Address('TCP', self.lookups[hostName], portNumber)
                )
                resolutionReceiver.resolutionComplete()
                return resolution

        self.nameResolver = Resolver()
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

    pool.runWithConnection = runWithConnection
    pool.runInteraction = runInteraction

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
    pool.threadpool = ThreadPool()
    pool.running = True
    return d


def get_clock():
    clock = ThreadedMemoryReactorClock()
    hs_clock = Clock(clock)
    return (clock, hs_clock)
