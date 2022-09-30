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
import unittest as stdlib_unittest

from pydantic import BaseModel, ValidationError
from typing_extensions import Literal

from synapse.rest.client.models import EmailRequestTokenBody


class ThreepidMediumEnumTestCase(stdlib_unittest.TestCase):
    class Model(BaseModel):
        medium: Literal["email", "msisdn"]

    def test_accepts_valid_medium_string(self) -> None:
        """Sanity check that Pydantic behaves sensibly with an enum-of-str

        This is arguably more of a test of a class that inherits from str and Enum
        simultaneously.
        """
        model = self.Model.parse_obj({"medium": "email"})
        self.assertEqual(model.medium, "email")

    def test_rejects_invalid_medium_value(self) -> None:
        with self.assertRaises(ValidationError):
            self.Model.parse_obj({"medium": "interpretive_dance"})

    def test_rejects_invalid_medium_type(self) -> None:
        with self.assertRaises(ValidationError):
            self.Model.parse_obj({"medium": 123})


class EmailRequestTokenBodyTestCase(stdlib_unittest.TestCase):
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
