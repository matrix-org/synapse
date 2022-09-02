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
import unittest

from pydantic import ValidationError

from synapse.rest.client.models import EmailRequestTokenBody


class EmailRequestTokenBodyTestCase(unittest.TestCase):
    base_request = {
        "client_secret": "hunter2",
        "email": "alice@wonderland.com",
        "send_attempt": 1,
    }

    def test_token_required_if_id_server_provided(self) -> None:
        with self.assertRaises(ValidationError):
            EmailRequestTokenBody.parse_obj(
                {
                    **self.base_request,
                    "id_server": "identity.wonderland.com",
                }
            )
        with self.assertRaises(ValidationError):
            EmailRequestTokenBody.parse_obj(
                {
                    **self.base_request,
                    "id_server": "identity.wonderland.com",
                    "id_access_token": None,
                }
            )

    def test_token_typechecked_when_id_server_provided(self) -> None:
        with self.assertRaises(ValidationError):
            EmailRequestTokenBody.parse_obj(
                {
                    **self.base_request,
                    "id_server": "identity.wonderland.com",
                    "id_access_token": 1337,
                }
            )
