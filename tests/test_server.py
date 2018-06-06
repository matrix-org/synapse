import attr
import re
import json

from mock import Mock
from io import BytesIO
from tests import unittest

from twisted.internet.defer import Deferred
from twisted.test.proto_helpers import MemoryReactorClock

from synapse.api.ratelimiting import Ratelimiter
from synapse.server import HomeServer

from synapse.api.errors import SynapseError, Codes
from synapse.util import Clock
from synapse.http.site import SynapseRequest
from synapse.http.server import JsonResource

from six import text_type


@attr.s
class FakeChannel(object):

    result = attr.ib(factory=dict)

    def writeHeaders(self, version, code, reason, headers):
        self.result["version"] = version
        self.result["code"] = code
        self.result["reason"] = reason
        self.result["headers"] = headers

    def write(self, content):
        if "body" not in self.result:
            self.result["body"] = b""

        self.result["body"] += content

    def requestDone(self, _self):
        self.result["done"] = True

    def getPeer(self):
        return None

    def getHost(self):
        return None

    @property
    def transport(self):
        return self


class FakeSite:

    server_version_string = b"1"
    site_tag = "test"

    @property
    def access_logger(self):
        class FakeLogger:
            def info(self, *args, **kwargs):
                pass

        return FakeLogger()


@attr.s
class FakeHomeserver(HomeServer):

    _reactor = attr.ib()
    hostname = attr.ib(default="localhost")
    _building = attr.ib(default=attr.Factory(dict))
    ratelimiter = attr.ib(default=attr.Factory(Ratelimiter))

    version_string = b"1"
    distributor = ""

    @property
    def config(self):
        m = Mock()
        m.enable_registration = True
        m.password_providers = []
        return m

    def get_clock(self):
        return Clock(self._reactor)


def make_request(method, path, content=b""):

    if isinstance(content, text_type):
        content = content.encode('utf8')

    site = FakeSite()
    channel = FakeChannel()

    req = SynapseRequest(site, channel)
    req.process = lambda: b""
    req.content = BytesIO(content)
    req.requestReceived(method, path, b"1.1")

    return req, channel


class JsonResourceTests(unittest.TestCase):
    def setUp(self):
        self.reactor = MemoryReactorClock()
        self.homeserver = FakeHomeserver(self.reactor)

    def test_handler_for_request(self):
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """
        got_kwargs = {}

        def _callback(request, **kwargs):
            got_kwargs.update(kwargs)
            return (200, kwargs)

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/foo/(?P<room_id>[^/]*)$")], _callback)

        request, channel = make_request(b"GET", b"/foo/%E2%98%83?a=%E2%98%83")
        request.render(res)

        self.assertEqual(request.args, {b'a': [u"\N{SNOWMAN}".encode('utf8')]})
        self.assertEqual(got_kwargs, {u"room_id": u"\N{SNOWMAN}"})

    def test_callback_direct_exception(self):
        """
        If the web callback raises an uncaught exception, it will be translated
        into a 500.
        """

        def _callback(request, **kwargs):
            raise Exception("boo")

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/foo$")], _callback)

        request, channel = make_request(b"GET", b"/foo")
        request.render(res)

        self.assertEqual(channel.result["code"], b'500')

    def test_callback_indirect_exception(self):
        """
        If the web callback raises an uncaught exception in a Deferred, it will
        be translated into a 500.
        """

        def _throw(*args):
            raise Exception("boo")

        def _callback(request, **kwargs):
            d = Deferred()
            d.addCallback(_throw)
            self.reactor.callLater(1, d.callback, True)
            return d

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/foo$")], _callback)

        request, channel = make_request(b"GET", b"/foo")
        request.render(res)

        # No error has been raised yet
        self.assertTrue("code" not in channel.result)

        # Advance time, now there's an error
        self.reactor.advance(1)
        self.assertEqual(channel.result["code"], b'500')

    def test_callback_synapseerror(self):
        """
        If the web callback raises a SynapseError, it returns the appropriate
        status code and message set in it.
        """

        def _callback(request, **kwargs):
            raise SynapseError(403, "Forbidden!!one!", Codes.FORBIDDEN)

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/foo$")], _callback)

        request, channel = make_request(b"GET", b"/foo")
        request.render(res)

        self.assertEqual(channel.result["code"], b'403')
        reply_body = json.loads(channel.result["body"])
        self.assertEqual(reply_body["error"], "Forbidden!!one!")
        self.assertEqual(reply_body["errcode"], "M_FORBIDDEN")

    def test_no_handler(self):
        """
        If there is no handler to process the request, Synapse will return 400.
        """

        def _callback(request, **kwargs):
            """
            Not ever actually called!
            """
            self.fail("shouldn't ever get here")

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/foo$")], _callback)

        request, channel = make_request(b"GET", b"/foobar")
        request.render(res)

        self.assertEqual(channel.result["code"], b'400')
        reply_body = json.loads(channel.result["body"])
        self.assertEqual(reply_body["error"], "Unrecognized request")
        self.assertEqual(reply_body["errcode"], "M_UNRECOGNIZED")
