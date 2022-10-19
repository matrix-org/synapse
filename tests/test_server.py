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
from http import HTTPStatus
from typing import Awaitable, Callable, Dict, NoReturn, Optional, Tuple

from twisted.internet.defer import Deferred
from twisted.web.resource import Resource

from synapse.api.errors import Codes, RedirectException, SynapseError
from synapse.config.server import parse_listener_def
from synapse.http.server import (
    DirectServeHtmlResource,
    DirectServeJsonResource,
    JsonResource,
    OptionsResource,
)
from synapse.http.site import SynapseRequest, SynapseSite
from synapse.logging.context import make_deferred_yieldable
from synapse.types import JsonDict
from synapse.util import Clock
from synapse.util.cancellation import cancellable

from tests import unittest
from tests.http.server._base import test_disconnect
from tests.server import (
    FakeChannel,
    FakeSite,
    ThreadedMemoryReactorClock,
    make_request,
    setup_test_homeserver,
)


class JsonResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reactor = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.reactor)
        self.homeserver = setup_test_homeserver(
            self.addCleanup,
            federation_http_client=None,
            clock=self.hs_clock,
            reactor=self.reactor,
        )

    def test_handler_for_request(self) -> None:
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """
        got_kwargs = {}

        def _callback(
            request: SynapseRequest, **kwargs: object
        ) -> Tuple[int, Dict[str, object]]:
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
            self.reactor,
            FakeSite(res, self.reactor),
            b"GET",
            b"/_matrix/foo/%E2%98%83?a=%E2%98%83",
        )

        self.assertEqual(got_kwargs, {"room_id": "\N{SNOWMAN}"})

    def test_callback_direct_exception(self) -> None:
        """
        If the web callback raises an uncaught exception, it will be translated
        into a 500.
        """

        def _callback(request: SynapseRequest, **kwargs: object) -> NoReturn:
            raise Exception("boo")

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 500)

    def test_callback_indirect_exception(self) -> None:
        """
        If the web callback raises an uncaught exception in a Deferred, it will
        be translated into a 500.
        """

        def _throw(*args: object) -> NoReturn:
            raise Exception("boo")

        def _callback(request: SynapseRequest, **kwargs: object) -> "Deferred[None]":
            d: "Deferred[None]" = Deferred()
            d.addCallback(_throw)
            self.reactor.callLater(0.5, d.callback, True)
            return make_deferred_yieldable(d)

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 500)

    def test_callback_synapseerror(self) -> None:
        """
        If the web callback raises a SynapseError, it returns the appropriate
        status code and message set in it.
        """

        def _callback(request: SynapseRequest, **kwargs: object) -> NoReturn:
            raise SynapseError(403, "Forbidden!!one!", Codes.FORBIDDEN)

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 403)
        self.assertEqual(channel.json_body["error"], "Forbidden!!one!")
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")

    def test_no_handler(self) -> None:
        """
        If there is no handler to process the request, Synapse will return 400.
        """

        def _callback(request: SynapseRequest, **kwargs: object) -> None:
            """
            Not ever actually called!
            """
            self.fail("shouldn't ever get here")

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foobar"
        )

        self.assertEqual(channel.code, 400)
        self.assertEqual(channel.json_body["error"], "Unrecognized request")
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")

    def test_head_request(self) -> None:
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """

        def _callback(
            request: SynapseRequest, **kwargs: object
        ) -> Tuple[int, Dict[str, object]]:
            return 200, {"result": True}

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET",
            [re.compile("^/_matrix/foo$")],
            _callback,
            "test_servlet",
        )

        # The path was registered as GET, but this is a HEAD request.
        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"HEAD", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 200)
        self.assertNotIn("body", channel.result)


class OptionsResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reactor = ThreadedMemoryReactorClock()

        class DummyResource(Resource):
            isLeaf = True

            def render(self, request: SynapseRequest) -> bytes:
                # Type-ignore: mypy thinks request.path is Optional[Any], not bytes.
                return request.path  # type: ignore[return-value]

        # Setup a resource with some children.
        self.resource = OptionsResource()
        self.resource.putChild(b"res", DummyResource())

    def _make_request(
        self, method: bytes, path: bytes, experimental_cors_msc3886: bool = False
    ) -> FakeChannel:
        """Create a request from the method/path and return a channel with the response."""
        # Create a site and query for the resource.
        site = SynapseSite(
            "test",
            "site_tag",
            parse_listener_def(
                0,
                {
                    "type": "http",
                    "port": 0,
                    "experimental_cors_msc3886": experimental_cors_msc3886,
                },
            ),
            self.resource,
            "1.0",
            max_request_body_size=4096,
            reactor=self.reactor,
        )

        # render the request and return the channel
        channel = make_request(self.reactor, site, method, path, shorthand=False)
        return channel

    def _check_cors_standard_headers(self, channel: FakeChannel) -> None:
        # Ensure the correct CORS headers have been added
        # as per https://spec.matrix.org/v1.4/client-server-api/#web-browser-clients
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Origin"),
            [b"*"],
            "has correct CORS Origin header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Methods"),
            [b"GET, HEAD, POST, PUT, DELETE, OPTIONS"],  # HEAD isn't in the spec
            "has correct CORS Methods header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Headers"),
            [b"X-Requested-With, Content-Type, Authorization, Date"],
            "has correct CORS Headers header",
        )

    def _check_cors_msc3886_headers(self, channel: FakeChannel) -> None:
        # Ensure the correct CORS headers have been added
        # as per https://github.com/matrix-org/matrix-spec-proposals/blob/hughns/simple-rendezvous-capability/proposals/3886-simple-rendezvous-capability.md#cors
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Origin"),
            [b"*"],
            "has correct CORS Origin header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Methods"),
            [b"GET, HEAD, POST, PUT, DELETE, OPTIONS"],  # HEAD isn't in the spec
            "has correct CORS Methods header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Headers"),
            [
                b"X-Requested-With, Content-Type, Authorization, Date, If-Match, If-None-Match"
            ],
            "has correct CORS Headers header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Expose-Headers"),
            [b"ETag, Location, X-Max-Bytes"],
            "has correct CORS Expose Headers header",
        )

    def test_unknown_options_request(self) -> None:
        """An OPTIONS requests to an unknown URL still returns 204 No Content."""
        channel = self._make_request(b"OPTIONS", b"/foo/")
        self.assertEqual(channel.code, 204)
        self.assertNotIn("body", channel.result)

        self._check_cors_standard_headers(channel)

    def test_known_options_request(self) -> None:
        """An OPTIONS requests to an known URL still returns 204 No Content."""
        channel = self._make_request(b"OPTIONS", b"/res/")
        self.assertEqual(channel.code, 204)
        self.assertNotIn("body", channel.result)

        self._check_cors_standard_headers(channel)

    def test_known_options_request_msc3886(self) -> None:
        """An OPTIONS requests to an known URL still returns 204 No Content."""
        channel = self._make_request(
            b"OPTIONS", b"/res/", experimental_cors_msc3886=True
        )
        self.assertEqual(channel.code, 204)
        self.assertNotIn("body", channel.result)

        self._check_cors_msc3886_headers(channel)

    def test_unknown_request(self) -> None:
        """A non-OPTIONS request to an unknown URL should 404."""
        channel = self._make_request(b"GET", b"/foo/")
        self.assertEqual(channel.code, 404)

    def test_known_request(self) -> None:
        """A non-OPTIONS request to an known URL should query the proper resource."""
        channel = self._make_request(b"GET", b"/res/")
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], b"/res/")


class WrapHtmlRequestHandlerTests(unittest.TestCase):
    class TestResource(DirectServeHtmlResource):
        callback: Optional[Callable[..., Awaitable[None]]]

        async def _async_render_GET(self, request: SynapseRequest) -> None:
            assert self.callback is not None
            await self.callback(request)

    def setUp(self) -> None:
        self.reactor = ThreadedMemoryReactorClock()

    def test_good_response(self) -> None:
        async def callback(request: SynapseRequest) -> None:
            request.write(b"response")
            request.finish()

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/path"
        )

        self.assertEqual(channel.code, 200)
        body = channel.result["body"]
        self.assertEqual(body, b"response")

    def test_redirect_exception(self) -> None:
        """
        If the callback raises a RedirectException, it is turned into a 30x
        with the right location.
        """

        async def callback(request: SynapseRequest, **kwargs: object) -> None:
            raise RedirectException(b"/look/an/eagle", 301)

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/path"
        )

        self.assertEqual(channel.code, 301)
        headers = channel.result["headers"]
        location_headers = [v for k, v in headers if k == b"Location"]
        self.assertEqual(location_headers, [b"/look/an/eagle"])

    def test_redirect_exception_with_cookie(self) -> None:
        """
        If the callback raises a RedirectException which sets a cookie, that is
        returned too
        """

        async def callback(request: SynapseRequest, **kwargs: object) -> NoReturn:
            e = RedirectException(b"/no/over/there", 304)
            e.cookies.append(b"session=yespls")
            raise e

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/path"
        )

        self.assertEqual(channel.code, 304)
        headers = channel.result["headers"]
        location_headers = [v for k, v in headers if k == b"Location"]
        self.assertEqual(location_headers, [b"/no/over/there"])
        cookies_headers = [v for k, v in headers if k == b"Set-Cookie"]
        self.assertEqual(cookies_headers, [b"session=yespls"])

    def test_head_request(self) -> None:
        """A head request should work by being turned into a GET request."""

        async def callback(request: SynapseRequest) -> None:
            request.write(b"response")
            request.finish()

        res = WrapHtmlRequestHandlerTests.TestResource()
        res.callback = callback

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"HEAD", b"/path"
        )

        self.assertEqual(channel.code, 200)
        self.assertNotIn("body", channel.result)


class CancellableDirectServeJsonResource(DirectServeJsonResource):
    def __init__(self, clock: Clock):
        super().__init__()
        self.clock = clock

    @cancellable
    async def _async_render_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}

    async def _async_render_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}


class CancellableDirectServeHtmlResource(DirectServeHtmlResource):
    ERROR_TEMPLATE = "{code} {msg}"

    def __init__(self, clock: Clock):
        super().__init__()
        self.clock = clock

    @cancellable
    async def _async_render_GET(self, request: SynapseRequest) -> Tuple[int, bytes]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, b"ok"

    async def _async_render_POST(self, request: SynapseRequest) -> Tuple[int, bytes]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, b"ok"


class DirectServeJsonResourceCancellationTests(unittest.TestCase):
    """Tests for `DirectServeJsonResource` cancellation."""

    def setUp(self) -> None:
        self.reactor = ThreadedMemoryReactorClock()
        self.clock = Clock(self.reactor)
        self.resource = CancellableDirectServeJsonResource(self.clock)
        self.site = FakeSite(self.resource, self.reactor)

    def test_cancellable_disconnect(self) -> None:
        """Test that handlers with the `@cancellable` flag can be cancelled."""
        channel = make_request(
            self.reactor, self.site, "GET", "/sleep", await_result=False
        )
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=True,
            expected_body={"error": "Request cancelled", "errcode": Codes.UNKNOWN},
        )

    def test_uncancellable_disconnect(self) -> None:
        """Test that handlers without the `@cancellable` flag cannot be cancelled."""
        channel = make_request(
            self.reactor, self.site, "POST", "/sleep", await_result=False
        )
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=False,
            expected_body={"result": True},
        )


class DirectServeHtmlResourceCancellationTests(unittest.TestCase):
    """Tests for `DirectServeHtmlResource` cancellation."""

    def setUp(self) -> None:
        self.reactor = ThreadedMemoryReactorClock()
        self.clock = Clock(self.reactor)
        self.resource = CancellableDirectServeHtmlResource(self.clock)
        self.site = FakeSite(self.resource, self.reactor)

    def test_cancellable_disconnect(self) -> None:
        """Test that handlers with the `@cancellable` flag can be cancelled."""
        channel = make_request(
            self.reactor, self.site, "GET", "/sleep", await_result=False
        )
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=True,
            expected_body=b"499 Request cancelled",
        )

    def test_uncancellable_disconnect(self) -> None:
        """Test that handlers without the `@cancellable` flag cannot be cancelled."""
        channel = make_request(
            self.reactor, self.site, "POST", "/sleep", await_result=False
        )
        test_disconnect(
            self.reactor, channel, expect_cancellation=False, expected_body=b"ok"
        )
