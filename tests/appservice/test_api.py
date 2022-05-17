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
from typing import Any, List, Mapping
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

from synapse.appservice import ApplicationService
from synapse.appservice.api import ApplicationServiceApi
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest

PROTOCOL = "myproto"
TOKEN = "myastoken"
URL = "http://mytestservice"
URL_USER = f"{URL}/_matrix/app/unstable/thirdparty/user/{PROTOCOL}"
URL_LOCATION = f"{URL}/_matrix/app/unstable/thirdparty/location/{PROTOCOL}"
SUCCESS_RESULT_USER = [
    {
        "protocol": PROTOCOL,
        "userid": "@a:user",
        "fields": {
            "more": "fields",
        },
    }
]
SUCCESS_RESULT_LOCATION = [
    {
        "protocol": PROTOCOL,
        "alias": "#a:room",
        "fields": {
            "more": "fields",
        },
    }
]


class ApplicationServiceApiTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.api = ApplicationServiceApi(hs)

        self.request_url = None
        self.fields = None

        async def get_json(url: str, args: Mapping[Any, Any]) -> List[JsonDict]:
            if not args.get(b"access_token"):
                raise Exception("Access token not provided")

            self.assertEqual(args.get(b"access_token"), TOKEN)
            self.request_url = url
            self.fields = args
            if url == URL_USER:
                return SUCCESS_RESULT_USER
            elif url == URL_LOCATION:
                return SUCCESS_RESULT_LOCATION
            else:
                self.fail("URL provided was invalid")
                return []

        self.api.get_json = Mock(side_effect=get_json)  # type: ignore[assignment]  # We assign to a method.
        self.service = ApplicationService(
            id="unique_identifier",
            sender="@as:test",
            url=URL,
            token="unused",
            hs_token=TOKEN,
            hostname="myserver",
        )

    def test_query_3pe_authenticates_token(self):
        result = self.get_success(
            self.api.query_3pe(self.service, "user", PROTOCOL, {b"some": [b"field"]})
        )
        self.assertEqual(self.request_url, URL_USER)
        self.assertEqual(result, SUCCESS_RESULT_USER)
        result = self.get_success(
            self.api.query_3pe(
                self.service, "location", PROTOCOL, {b"some": [b"field"]}
            )
        )
        self.assertEqual(self.request_url, URL_LOCATION)
        self.assertEqual(result, SUCCESS_RESULT_LOCATION)
