# Copyright 2022 The Matrix.org Foundation C.I.C
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
from unittest.mock import Mock

from synapse.rest import admin
from synapse.rest.client import account_data, login, room

from tests import unittest
from tests.test_utils import make_awaitable


class AccountDataTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        account_data.register_servlets,
    ]

    def test_on_account_data_updated_callback(self) -> None:
        """Tests that the on_account_data_updated module callback is called correctly when
        a user's account data changes.
        """
        mocked_callback = Mock(return_value=make_awaitable(None))
        self.hs.get_account_data_handler()._on_account_data_updated_callbacks.append(
            mocked_callback
        )

        user_id = self.register_user("user", "password")
        tok = self.login("user", "password")
        account_data_type = "org.matrix.foo"
        account_data_content = {"bar": "baz"}

        # Change the user's global account data.
        channel = self.make_request(
            "PUT",
            f"/user/{user_id}/account_data/{account_data_type}",
            account_data_content,
            access_token=tok,
        )

        # Test that the callback is called with the user ID, the new account data, and
        # None as the room ID.
        self.assertEqual(channel.code, 200, channel.result)
        mocked_callback.assert_called_once_with(
            user_id, None, account_data_type, account_data_content
        )

        # Change the user's room-specific account data.
        room_id = self.helper.create_room_as(user_id, tok=tok)
        channel = self.make_request(
            "PUT",
            f"/user/{user_id}/rooms/{room_id}/account_data/{account_data_type}",
            account_data_content,
            access_token=tok,
        )

        # Test that the callback is called with the user ID, the room ID and the new
        # account data.
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(mocked_callback.call_count, 2)
        mocked_callback.assert_called_with(
            user_id, room_id, account_data_type, account_data_content
        )
