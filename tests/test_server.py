import attr
import re
from tests import unittest

from twisted.test.proto_helpers import MemoryReactorClock

from synapse.util import Clock
from synapse.http.site import SynapseRequest
from synapse.http.server import JsonResource

class JsonResourceTests(unittest.TestCase):

    def test_handler_for_request(self):

        reactor = MemoryReactorClock()

        class FakeHomeserver:
            @classmethod
            def get_clock(cls):
                return Clock(reactor)

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

            pass

        channel = FakeChannel()
        req = SynapseRequest(FakeSite(), channel)

        req.method = b"GET"
        req.path = b"/foo"

        res = JsonResource(FakeHomeserver)


        def _callback(request, **kwargs):
            return (200, b"HI!")

        res.register_paths("GET", [re.compile("^/foo")], _callback)
        req.render(res)
