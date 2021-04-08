# -*- coding: utf-8 -*-
# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
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

from synapse.api.constants import UserTypes
from synapse.api.errors import ThreepidValidationError

from tests.unittest import HomeserverTestCase


class RegistrationStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.user_id = "@my-user:test"
        self.tokens = ["AbCdEfGhIjKlMnOpQrStUvWxYz", "BcDeFgHiJkLmNoPqRsTuVwXyZa"]
        self.pwhash = "{xx1}123456789"
        self.device_id = "akgjhdjklgshg"

    def test_register(self):
        self.get_success(self.store.register_user(self.user_id, self.pwhash))

        self.assertEquals(
            {
                # TODO(paul): Surely this field should be 'user_id', not 'name'
                "name": self.user_id,
                "password_hash": self.pwhash,
                "admin": 0,
                "is_guest": 0,
                "consent_version": None,
                "consent_server_notice_sent": None,
                "appservice_id": None,
                "creation_ts": 0,
                "user_type": None,
                "deactivated": 0,
                "shadow_banned": 0,
            },
            (self.get_success(self.store.get_user_by_id(self.user_id))),
        )

    def test_add_tokens(self):
        self.get_success(self.store.register_user(self.user_id, self.pwhash))
        self.get_success(
            self.store.add_access_token_to_user(
                self.user_id, self.tokens[1], self.device_id, valid_until_ms=None
            )
        )

        result = self.get_success(self.store.get_user_by_access_token(self.tokens[1]))

        self.assertEqual(result.user_id, self.user_id)
        self.assertEqual(result.device_id, self.device_id)
        self.assertIsNotNone(result.token_id)

    def test_user_delete_access_tokens(self):
        # add some tokens
        self.get_success(self.store.register_user(self.user_id, self.pwhash))
        self.get_success(
            self.store.add_access_token_to_user(
                self.user_id, self.tokens[0], device_id=None, valid_until_ms=None
            )
        )
        self.get_success(
            self.store.add_access_token_to_user(
                self.user_id, self.tokens[1], self.device_id, valid_until_ms=None
            )
        )

        # now delete some
        self.get_success(
            self.store.user_delete_access_tokens(self.user_id, device_id=self.device_id)
        )

        # check they were deleted
        user = self.get_success(self.store.get_user_by_access_token(self.tokens[1]))
        self.assertIsNone(user, "access token was not deleted by device_id")

        # check the one not associated with the device was not deleted
        user = self.get_success(self.store.get_user_by_access_token(self.tokens[0]))
        self.assertEqual(self.user_id, user.user_id)

        # now delete the rest
        self.get_success(self.store.user_delete_access_tokens(self.user_id))

        user = self.get_success(self.store.get_user_by_access_token(self.tokens[0]))
        self.assertIsNone(user, "access token was not deleted without device_id")

    def test_is_support_user(self):
        TEST_USER = "@test:test"
        SUPPORT_USER = "@support:test"

        res = self.get_success(self.store.is_support_user(None))
        self.assertFalse(res)
        self.get_success(
            self.store.register_user(user_id=TEST_USER, password_hash=None)
        )
        res = self.get_success(self.store.is_support_user(TEST_USER))
        self.assertFalse(res)

        self.get_success(
            self.store.register_user(
                user_id=SUPPORT_USER, password_hash=None, user_type=UserTypes.SUPPORT
            )
        )
        res = self.get_success(self.store.is_support_user(SUPPORT_USER))
        self.assertTrue(res)

    def test_3pid_inhibit_invalid_validation_session_error(self):
        """Tests that enabling the configuration option to inhibit 3PID errors on
        /requestToken also inhibits validation errors caused by an unknown session ID.
        """

        # Check that, with the config setting set to false (the default value), a
        # validation error is caused by the unknown session ID.
        e = self.get_failure(
            self.store.validate_threepid_session(
                "fake_sid",
                "fake_client_secret",
                "fake_token",
                0,
            ),
            ThreepidValidationError,
        )
        self.assertEquals(e.value.msg, "Unknown session_id", e)

        # Set the config setting to true.
        self.store._ignore_unknown_session_error = True

        # Check that now the validation error is caused by the token not matching.
        e = self.get_failure(
            self.store.validate_threepid_session(
                "fake_sid",
                "fake_client_secret",
                "fake_token",
                0,
            ),
            ThreepidValidationError,
        )
        self.assertEquals(e.value.msg, "Validation token not found or has expired", e)
