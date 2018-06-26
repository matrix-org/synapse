import json
import re

from twisted.internet.defer import Deferred
from twisted.test.proto_helpers import MemoryReactorClock

from synapse.util import Clock
from synapse.api.errors import Codes, SynapseError
from synapse.http.server import JsonResource
from tests import unittest
from tests.server import make_request, setup_test_homeserver


class JsonResourceTests(unittest.TestCase):
    def setUp(self):
        self.reactor = MemoryReactorClock()
        self.hs_clock = Clock(self.reactor)
        self.homeserver = setup_test_homeserver(
            http_client=None, clock=self.hs_clock, reactor=self.reactor
        )

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
