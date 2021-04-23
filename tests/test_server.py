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

import re

from twisted.internet.defer import Deferred
from twisted.web.resource import Resource

from synapse.api.errors import Codes, RedirectException, SynapseError
from synapse.config.server import parse_listener_def
from synapse.http.server import DirectServeHtmlResource, JsonResource, OptionsResource
from synapse.http.site import SynapseSite
from synapse.logging.context import make_deferred_yieldable
from synapse.util import Clock

from tests import unittest
from tests.server import (
    FakeSite,
    ThreadedMemoryReactorClock,
    make_request,
    setup_test_homeserver,
)


class JsonResourceTests(unittest.TestCase):
    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.reactor)
        self.homeserver = setup_test_homeserver(
            self.addCleanup,
            federation_http_client=None,
            clock=self.hs_clock,
            reactor=self.reactor,
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

        make_request(
            self.reactor, FakeSite(res), b"GET", b"/_matrix/foo/%E2%98%83?a=%E2%98%83"
        )

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

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/_matrix/foo")

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

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/_matrix/foo")

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

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/_matrix/foo")

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

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/_matrix/foobar")

        self.assertEqual(channel.result["code"], b"400")
        self.assertEqual(channel.json_body["error"], "Unrecognized request")
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")

    def test_head_request(self):
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """

        def _callback(request, **kwargs):
            return 200, {"result": True}

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET",
            [re.compile("^/_matrix/foo$")],
            _callback,
            "test_servlet",
        )

        # The path was registered as GET, but this is a HEAD request.
        channel = make_request(self.reactor, FakeSite(res), b"HEAD", b"/_matrix/foo")

        self.assertEqual(channel.result["code"], b"200")
        self.assertNotIn("body", channel.result)


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
        # Create a site and query for the resource.
        site = SynapseSite(
            "test",
            "site_tag",
            parse_listener_def({"type": "http", "port": 0}),
            self.resource,
            "1.0",
        )

        # render the request and return the channel
        channel = make_request(self.reactor, site, method, path, shorthand=False)
        return channel

    def test_unknown_options_request(self):
        """An OPTIONS requests to an unknown URL still returns 204 No Content."""
        channel = self._make_request(b"OPTIONS", b"/foo/")
        self.assertEqual(channel.result["code"], b"204")
        self.assertNotIn("body", channel.result)

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
        """An OPTIONS requests to an known URL still returns 204 No Content."""
        channel = self._make_request(b"OPTIONS", b"/res/")
        self.assertEqual(channel.result["code"], b"204")
        self.assertNotIn("body", channel.result)

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
    class TestResource(DirectServeHtmlResource):
        callback = None

        async def _async_render_GET(self, request):
            await self.callback(request)

    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()

    def test_good_response(self):
        async def callback(request):
            request.write(b"response")
            request.finish()

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/path")

        self.assertEqual(channel.result["code"], b"200")
        body = channel.result["body"]
        self.assertEqual(body, b"response")

    def test_redirect_exception(self):
        """
        If the callback raises a RedirectException, it is turned into a 30x
        with the right location.
        """

        async def callback(request, **kwargs):
            raise RedirectException(b"/look/an/eagle", 301)

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/path")

        self.assertEqual(channel.result["code"], b"301")
        headers = channel.result["headers"]
        location_headers = [v for k, v in headers if k == b"Location"]
        self.assertEqual(location_headers, [b"/look/an/eagle"])

    def test_redirect_exception_with_cookie(self):
        """
        If the callback raises a RedirectException which sets a cookie, that is
        returned too
        """

        async def callback(request, **kwargs):
            e = RedirectException(b"/no/over/there", 304)
            e.cookies.append(b"session=yespls")
            raise e

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(self.reactor, FakeSite(res), b"GET", b"/path")

        self.assertEqual(channel.result["code"], b"304")
        headers = channel.result["headers"]
        location_headers = [v for k, v in headers if k == b"Location"]
        self.assertEqual(location_headers, [b"/no/over/there"])
        cookies_headers = [v for k, v in headers if k == b"Set-Cookie"]
        self.assertEqual(cookies_headers, [b"session=yespls"])

    def test_head_request(self):
        """A head request should work by being turned into a GET request."""

        async def callback(request):
            request.write(b"response")
            request.finish()

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(self.reactor, FakeSite(res), b"HEAD", b"/path")

        self.assertEqual(channel.result["code"], b"200")
        self.assertNotIn("body", channel.result)
