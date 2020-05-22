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

from synapse.api.errors import Codes, RedirectException, SynapseError
from synapse.http.server import (
    DirectServeResource,
    JsonResource,
    OptionsResource,
    wrap_html_request_handler,
)
from synapse.http.site import SynapseSite, logger
from synapse.logging.context import make_deferred_yieldable
from synapse.util import Clock

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
            return 200, kwargs

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET",
            [re.compile("^/_matrix/foo/(?P<room_id>[^/]*)$")],
            _callback,
            "test_servlet",
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
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

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
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

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
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

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
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        request, channel = make_request(self.reactor, b"GET", b"/_matrix/foobar")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"400")
        self.assertEqual(channel.json_body["error"], "Unrecognized request")
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")


class OptionsResourceTests(unittest.TestCase):
    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()

        class DummyResource(Resource):
            isLeaf = True

            def render(self, request):
                return request.path

        # Setup a resource with some children.
        self.resource = OptionsResource()
        self.resource.putChild(b"res", DummyResource())

    def _make_request(self, method, path):
        """Create a request from the method/path and return a channel with the response."""
        request, channel = make_request(self.reactor, method, path, shorthand=False)
        request.prepath = []  # This doesn't get set properly by make_request.

        # Create a site and query for the resource.
        site = SynapseSite("test", "site_tag", {}, self.resource, "1.0")
        request.site = site
        resource = site.getResourceFor(request)

        # Finally, render the resource and return the channel.
        render(request, resource, self.reactor)
        return channel

    def test_unknown_options_request(self):
        """An OPTIONS requests to an unknown URL still returns 200 OK."""
        channel = self._make_request(b"OPTIONS", b"/foo/")
        self.assertEqual(channel.result["code"], b"200")
        self.assertEqual(channel.result["body"], b"{}")

        # Ensure the correct CORS headers have been added
        self.assertTrue(
            channel.headers.hasHeader(b"Access-Control-Allow-Origin"),
            "has CORS Origin header",
        )
        self.assertTrue(
            channel.headers.hasHeader(b"Access-Control-Allow-Methods"),
            "has CORS Methods header",
        )
        self.assertTrue(
            channel.headers.hasHeader(b"Access-Control-Allow-Headers"),
            "has CORS Headers header",
        )

    def test_known_options_request(self):
        """An OPTIONS requests to an known URL still returns 200 OK."""
        channel = self._make_request(b"OPTIONS", b"/res/")
        self.assertEqual(channel.result["code"], b"200")
        self.assertEqual(channel.result["body"], b"{}")

        # Ensure the correct CORS headers have been added
        self.assertTrue(
            channel.headers.hasHeader(b"Access-Control-Allow-Origin"),
            "has CORS Origin header",
        )
        self.assertTrue(
            channel.headers.hasHeader(b"Access-Control-Allow-Methods"),
            "has CORS Methods header",
        )
        self.assertTrue(
            channel.headers.hasHeader(b"Access-Control-Allow-Headers"),
            "has CORS Headers header",
        )

    def test_unknown_request(self):
        """A non-OPTIONS request to an unknown URL should 404."""
        channel = self._make_request(b"GET", b"/foo/")
        self.assertEqual(channel.result["code"], b"404")

    def test_known_request(self):
        """A non-OPTIONS request to an known URL should query the proper resource."""
        channel = self._make_request(b"GET", b"/res/")
        self.assertEqual(channel.result["code"], b"200")
        self.assertEqual(channel.result["body"], b"/res/")


class WrapHtmlRequestHandlerTests(unittest.TestCase):
    class TestResource(DirectServeResource):
        callback = None

        @wrap_html_request_handler
        async def _async_render_GET(self, request):
            return await self.callback(request)

    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()

    def test_good_response(self):
        def callback(request):
            request.write(b"response")
            request.finish()

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        request, channel = make_request(self.reactor, b"GET", b"/path")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"200")
        body = channel.result["body"]
        self.assertEqual(body, b"response")

    def test_redirect_exception(self):
        """
        If the callback raises a RedirectException, it is turned into a 30x
        with the right location.
        """

        def callback(request, **kwargs):
            raise RedirectException(b"/look/an/eagle", 301)

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        request, channel = make_request(self.reactor, b"GET", b"/path")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"301")
        headers = channel.result["headers"]
        location_headers = [v for k, v in headers if k == b"Location"]
        self.assertEqual(location_headers, [b"/look/an/eagle"])

    def test_redirect_exception_with_cookie(self):
        """
        If the callback raises a RedirectException which sets a cookie, that is
        returned too
        """

        def callback(request, **kwargs):
            e = RedirectException(b"/no/over/there", 304)
            e.cookies.append(b"session=yespls")
            raise e

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        request, channel = make_request(self.reactor, b"GET", b"/path")
        render(request, res, self.reactor)

        self.assertEqual(channel.result["code"], b"304")
        headers = channel.result["headers"]
        location_headers = [v for k, v in headers if k == b"Location"]
        self.assertEqual(location_headers, [b"/no/over/there"])
        cookies_headers = [v for k, v in headers if k == b"Set-Cookie"]
        self.assertEqual(cookies_headers, [b"session=yespls"])


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
