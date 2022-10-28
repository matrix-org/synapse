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
from typing import Any, List, Mapping, Sequence, Union
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

from synapse.appservice import ApplicationService
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest

PROTOCOL = "myproto"
TOKEN = "myastoken"
URL = "http://mytestservice"


class ApplicationServiceApiTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.api = hs.get_application_service_api()
        self.service = ApplicationService(
            id="unique_identifier",
            sender="@as:test",
            url=URL,
            token="unused",
            hs_token=TOKEN,
        )

    def test_query_3pe_authenticates_token(self):
        """
        Tests that 3pe queries to the appservice are authenticated
        with the appservice's token.
        """

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

        URL_USER = f"{URL}/_matrix/app/unstable/thirdparty/user/{PROTOCOL}"
        URL_LOCATION = f"{URL}/_matrix/app/unstable/thirdparty/location/{PROTOCOL}"

        self.request_url = None

        async def get_json(
            url: str,
            args: Mapping[Any, Any],
            headers: Mapping[Union[str, bytes], Sequence[Union[str, bytes]]],
        ) -> List[JsonDict]:
            # Ensure the access token is passed as both a header and query arg.
            if not headers.get("Authorization") or not args.get(b"access_token"):
                raise RuntimeError("Access token not provided")

            self.assertEqual(headers.get("Authorization"), [f"Bearer {TOKEN}"])
            self.assertEqual(args.get(b"access_token"), TOKEN)
            self.request_url = url
            if url == URL_USER:
                return SUCCESS_RESULT_USER
            elif url == URL_LOCATION:
                return SUCCESS_RESULT_LOCATION
            else:
                raise RuntimeError(
                    "URL provided was invalid. This should never be seen."
                )

        # We assign to a method, which mypy doesn't like.
        self.api.get_json = Mock(side_effect=get_json)  # type: ignore[assignment]

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
