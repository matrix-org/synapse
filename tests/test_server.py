import attr
import re
import json

from io import BytesIO
from tests import unittest

from twisted.test.proto_helpers import MemoryReactorClock

from synapse.util import Clock
from synapse.http.site import SynapseRequest
from synapse.http.server import JsonResource


@attr.s
class FakeChannel(object):

    result = attr.ib(factory=dict)

    def writeHeaders(self, version, code, reason, headers):
        self.result["version"] = version
        self.result["code"] = code
        self.result["reason"] = reason
        self.result["headers"] = headers

    def write(self, content):
        if not "body" in self.result:
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
class FakeHomeserver(object):

    _reactor = attr.ib()

    def get_clock(self):
        return Clock(self._reactor)


def make_request(method, path, content=b""):

    site = FakeSite()
    channel = FakeChannel()

    req = SynapseRequest(site, channel)
    req.process = lambda: b""
    req.content = BytesIO(content)
    req.requestReceived(method, path, b"1.1")

    return req, channel


class JsonResourceTests(unittest.TestCase):

    def test_handler_for_request(self):
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """
        reactor = MemoryReactorClock()
        homeserver = FakeHomeserver(reactor)

        request, channel = make_request(b"GET", b"/foo/%E2%98%83?a=%E2%98%83")
        got_kwargs = {}

        def _callback(request, **kwargs):
            got_kwargs.update(kwargs)
            return (200, kwargs)

        res = JsonResource(homeserver)
        res.register_paths(
            "GET", [re.compile(b"^/foo/(?P<room_id>[^/]*)$")], _callback)
        request.render(res)

        self.assertEqual(request.args, {b'a': [u"\N{SNOWMAN}".encode('utf8')]})
        self.assertEqual(got_kwargs, {u"room_id": u"\N{SNOWMAN}"})
