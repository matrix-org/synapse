# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from http import HTTPStatus
from typing import Dict, List, Tuple

from synapse.api.errors import Codes
from synapse.federation.transport.server import BaseFederationServlet
from synapse.federation.transport.server._base import Authenticator, _parse_auth_header
from synapse.http.server import JsonResource, cancellable
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util.ratelimitutils import FederationRateLimiter

from tests import unittest
from tests.http.server._base import test_disconnect


class CancellableFederationServlet(BaseFederationServlet):
    PATH = "/sleep"

    def __init__(
        self,
        hs: HomeServer,
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.clock = hs.get_clock()

    @cancellable
    async def on_GET(
        self, origin: str, content: None, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}

    async def on_POST(
        self, origin: str, content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}


class BaseFederationServletCancellationTests(unittest.FederatingHomeserverTestCase):
    """Tests for `BaseFederationServlet` cancellation."""

    skip = "`BaseFederationServlet` does not support cancellation yet."

    path = f"{CancellableFederationServlet.PREFIX}{CancellableFederationServlet.PATH}"

    def create_test_resource(self):
        """Overrides `HomeserverTestCase.create_test_resource`."""
        resource = JsonResource(self.hs)

        CancellableFederationServlet(
            hs=self.hs,
            authenticator=Authenticator(self.hs),
            ratelimiter=self.hs.get_federation_ratelimiter(),
            server_name=self.hs.hostname,
        ).register(resource)

        return resource

    def test_cancellable_disconnect(self) -> None:
        """Test that handlers with the `@cancellable` flag can be cancelled."""
        channel = self.make_signed_federation_request(
            "GET", self.path, await_result=False
        )

        # Advance past all the rate limiting logic. If we disconnect too early, the
        # request won't be processed.
        self.pump()

        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=True,
            expected_body={"error": "Request cancelled", "errcode": Codes.UNKNOWN},
        )

    def test_uncancellable_disconnect(self) -> None:
        """Test that handlers without the `@cancellable` flag cannot be cancelled."""
        channel = self.make_signed_federation_request(
            "POST",
            self.path,
            content={},
            await_result=False,
        )

        # Advance past all the rate limiting logic. If we disconnect too early, the
        # request won't be processed.
        self.pump()

        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=False,
            expected_body={"result": True},
        )


class BaseFederationAuthorizationTests(unittest.TestCase):
    def test_authorization_header(self) -> None:
        """Tests that the Authorization header is parsed correctly."""

        # test a "normal" Authorization header
        self.assertEqual(
            _parse_auth_header(
                b'X-Matrix origin=foo,key="ed25519:1",sig="sig",destination="bar"'
            ),
            ("foo", "ed25519:1", "sig", "bar"),
        )
        # test an Authorization with extra spaces, upper-case names, and escaped
        # characters
        self.assertEqual(
            _parse_auth_header(
                b'X-Matrix  ORIGIN=foo,KEY="ed25\\519:1",SIG="sig",destination="bar"'
            ),
            ("foo", "ed25519:1", "sig", "bar"),
        )
        self.assertEqual(
            _parse_auth_header(
                b'X-Matrix origin=foo,key="ed25519:1",sig="sig",destination="bar",extra_field=ignored'
            ),
            ("foo", "ed25519:1", "sig", "bar"),
        )
