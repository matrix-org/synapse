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
from typing import Tuple

from twisted.web.server import Request

from synapse.api.errors import Codes
from synapse.http.server import JsonResource
from synapse.replication.http import REPLICATION_PREFIX
from synapse.replication.http._base import ReplicationEndpoint
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util.cancellation import cancellable

from tests import unittest
from tests.http.server._base import test_disconnect


class CancellableReplicationEndpoint(ReplicationEndpoint):
    NAME = "cancellable_sleep"
    PATH_ARGS = ()
    CACHE = False

    def __init__(self, hs: HomeServer):
        super().__init__(hs)
        self.clock = hs.get_clock()

    @staticmethod
    async def _serialize_payload() -> JsonDict:
        return {}

    @cancellable
    async def _handle_request(  # type: ignore[override]
        self, request: Request
    ) -> Tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}


class UncancellableReplicationEndpoint(ReplicationEndpoint):
    NAME = "uncancellable_sleep"
    PATH_ARGS = ()
    CACHE = False

    def __init__(self, hs: HomeServer):
        super().__init__(hs)
        self.clock = hs.get_clock()

    @staticmethod
    async def _serialize_payload() -> JsonDict:
        return {}

    async def _handle_request(  # type: ignore[override]
        self, request: Request
    ) -> Tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}


class ReplicationEndpointCancellationTestCase(unittest.HomeserverTestCase):
    """Tests for `ReplicationEndpoint` cancellation."""

    def create_test_resource(self):
        """Overrides `HomeserverTestCase.create_test_resource`."""
        resource = JsonResource(self.hs)

        CancellableReplicationEndpoint(self.hs).register(resource)
        UncancellableReplicationEndpoint(self.hs).register(resource)

        return resource

    def test_cancellable_disconnect(self) -> None:
        """Test that handlers with the `@cancellable` flag can be cancelled."""
        path = f"{REPLICATION_PREFIX}/{CancellableReplicationEndpoint.NAME}/"
        channel = self.make_request("POST", path, await_result=False)
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=True,
            expected_body={"error": "Request cancelled", "errcode": Codes.UNKNOWN},
        )

    def test_uncancellable_disconnect(self) -> None:
        """Test that handlers without the `@cancellable` flag cannot be cancelled."""
        path = f"{REPLICATION_PREFIX}/{UncancellableReplicationEndpoint.NAME}/"
        channel = self.make_request("POST", path, await_result=False)
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=False,
            expected_body={"result": True},
        )
