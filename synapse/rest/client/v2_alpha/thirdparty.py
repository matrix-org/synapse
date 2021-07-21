# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.constants import ThirdPartyEntityKind
from synapse.http.servlet import RestServlet

from ._base import client_patterns

logger = logging.getLogger(__name__)


class ThirdPartyProtocolsServlet(RestServlet):
    PATTERNS = client_patterns("/thirdparty/protocols")

    def __init__(self, hs):
        super().__init__()

        self.auth = hs.get_auth()
        self.appservice_handler = hs.get_application_service_handler()

    async def on_GET(self, request):
        await self.auth.get_user_by_req(request, allow_guest=True)

        protocols = await self.appservice_handler.get_3pe_protocols()
        return 200, protocols


class ThirdPartyProtocolServlet(RestServlet):
    PATTERNS = client_patterns("/thirdparty/protocol/(?P<protocol>[^/]+)$")

    def __init__(self, hs):
        super().__init__()

        self.auth = hs.get_auth()
        self.appservice_handler = hs.get_application_service_handler()

    async def on_GET(self, request, protocol):
        await self.auth.get_user_by_req(request, allow_guest=True)

        protocols = await self.appservice_handler.get_3pe_protocols(
            only_protocol=protocol
        )
        if protocol in protocols:
            return 200, protocols[protocol]
        else:
            return 404, {"error": "Unknown protocol"}


class ThirdPartyUserServlet(RestServlet):
    PATTERNS = client_patterns("/thirdparty/user(/(?P<protocol>[^/]+))?$")

    def __init__(self, hs):
        super().__init__()

        self.auth = hs.get_auth()
        self.appservice_handler = hs.get_application_service_handler()

    async def on_GET(self, request, protocol):
        await self.auth.get_user_by_req(request, allow_guest=True)

        fields = request.args
        fields.pop(b"access_token", None)

        results = await self.appservice_handler.query_3pe(
            ThirdPartyEntityKind.USER, protocol, fields
        )

        return 200, results


class ThirdPartyLocationServlet(RestServlet):
    PATTERNS = client_patterns("/thirdparty/location(/(?P<protocol>[^/]+))?$")

    def __init__(self, hs):
        super().__init__()

        self.auth = hs.get_auth()
        self.appservice_handler = hs.get_application_service_handler()

    async def on_GET(self, request, protocol):
        await self.auth.get_user_by_req(request, allow_guest=True)

        fields = request.args
        fields.pop(b"access_token", None)

        results = await self.appservice_handler.query_3pe(
            ThirdPartyEntityKind.LOCATION, protocol, fields
        )

        return 200, results


def register_servlets(hs, http_server):
    ThirdPartyProtocolsServlet(hs).register(http_server)
    ThirdPartyProtocolServlet(hs).register(http_server)
    ThirdPartyUserServlet(hs).register(http_server)
    ThirdPartyLocationServlet(hs).register(http_server)
