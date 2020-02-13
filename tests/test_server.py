# Copyright 2018 New Vector Ltd
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
import re

from six import StringIO

from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
from twisted.test.proto_helpers import AccumulatingProtocol
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import JsonResource
from synapse.http.site import SynapseSite, logger
from synapse.util import Clock
from synapse.util.logcontext import make_deferred_yieldable

from tests import unittest
from tests.server import (
    FakeTransport,
    ThreadedMemoryReactorClock,
    make_request,
    render,
    setup_test_homeserver,
)


class JsonResourceTests(unittest.TestCase):
    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.reactor)
        self.homeserver = setup_test_homeserver(
            self.addCleanup, http_client=None, clock=self.hs_clock, reactor=self.reactor
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
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo/(?P<room_id>[^/]*)$")], _callback
        )

        request, channel = make_request(
            self.reactor, b"GET", b"/_matrix/foo/%E2%98%83?a=%E2%98%83"
        )
        render(request, res, self.reactor)

        self.assertEqual(request.args, {b"a": ["\N{SNOWMAN}".encode("utf8")]})
        self.assertEqual(got_kwargs, {"room_id": "\N{SNOWMAN}"})

    def test_callback_direct_exception(self):
        """
        If the web callback raises an uncaught exception, it will be translated
        into a 500.
        """

        def _callback(request, **kwargs):
            raise Exception("boo")

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/_matrix/foo$")], _callback)

        request, channel = make_request(self.reactor, b"GET", b"/_matrix/foo")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"500")

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
            return make_deferred_yieldable(d)

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/_matrix/foo$")], _callback)

        request, channel = make_request(self.reactor, b"GET", b"/_matrix/foo")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"500")

    def test_callback_synapseerror(self):
        """
        If the web callback raises a SynapseError, it returns the appropriate
        status code and message set in it.
        """

        def _callback(request, **kwargs):
            raise SynapseError(403, "Forbidden!!one!", Codes.FORBIDDEN)

        res = JsonResource(self.homeserver)
        res.register_paths("GET", [re.compile("^/_matrix/foo$")], _callback)

        request, channel = make_request(self.reactor, b"GET", b"/_matrix/foo")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"403")
        self.assertEqual(channel.json_body["error"], "Forbidden!!one!")
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")

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
        res.register_paths("GET", [re.compile("^/_matrix/foo$")], _callback)

        request, channel = make_request(self.reactor, b"GET", b"/_matrix/foobar")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"400")
        self.assertEqual(channel.json_body["error"], "Unrecognized request")
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")


class SiteTestCase(unittest.HomeserverTestCase):
    def test_lose_connection(self):
        """
        We log the URI correctly redacted when we lose the connection.
        """

        class HangingResource(Resource):
            """
            A Resource that strategically hangs, as if it were processing an
            answer.
            """

            def render(self, request):
                return NOT_DONE_YET

        # Set up a logging handler that we can inspect afterwards
        output = StringIO()
        handler = logging.StreamHandler(output)
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(10)
        self.addCleanup(logger.setLevel, old_level)
        self.addCleanup(logger.removeHandler, handler)

        # Make a resource and a Site, the resource will hang and allow us to
        # time out the request while it's 'processing'
        base_resource = Resource()
        base_resource.putChild(b"", HangingResource())
        site = SynapseSite("test", "site_tag", {}, base_resource, "1.0")

        server = site.buildProtocol(None)
        client = AccumulatingProtocol()
        client.makeConnection(FakeTransport(server, self.reactor))
        server.makeConnection(FakeTransport(client, self.reactor))

        # Send a request with an access token that will get redacted
        server.dataReceived(b"GET /?access_token=bar HTTP/1.0\r\n\r\n")
        self.pump()

        # Lose the connection
        e = Failure(Exception("Failed123"))
        server.connectionLost(e)
        handler.flush()

        # Our access token is redacted and the failure reason is logged.
        self.assertIn("/?access_token=<redacted>", output.getvalue())
        self.assertIn("Failed123", output.getvalue())
