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
from typing import Any

from twisted.web.server import Request

from synapse.http.additional_resource import AdditionalResource
from synapse.http.server import respond_with_json
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from tests.server import FakeSite, make_request
from tests.unittest import HomeserverTestCase


class _AsyncTestCustomEndpoint:
    def __init__(self, config: JsonDict, module_api: Any) -> None:
        pass

    async def handle_request(self, request: Request) -> None:
        assert isinstance(request, SynapseRequest)
        respond_with_json(request, 200, {"some_key": "some_value_async"})


class _SyncTestCustomEndpoint:
    def __init__(self, config: JsonDict, module_api: Any) -> None:
        pass

    async def handle_request(self, request: Request) -> None:
        assert isinstance(request, SynapseRequest)
        respond_with_json(request, 200, {"some_key": "some_value_sync"})


class AdditionalResourceTests(HomeserverTestCase):
    """Very basic tests that `AdditionalResource` works correctly with sync
    and async handlers.
    """

    def test_async(self) -> None:
        handler = _AsyncTestCustomEndpoint({}, None).handle_request
        resource = AdditionalResource(self.hs, handler)

        channel = make_request(
            self.reactor, FakeSite(resource, self.reactor), "GET", "/"
        )

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body, {"some_key": "some_value_async"})

    def test_sync(self) -> None:
        handler = _SyncTestCustomEndpoint({}, None).handle_request
        resource = AdditionalResource(self.hs, handler)

        channel = make_request(
            self.reactor, FakeSite(resource, self.reactor), "GET", "/"
        )

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body, {"some_key": "some_value_sync"})
