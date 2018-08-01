# -*- coding: utf-8 -*-
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

from mock import Mock

from twisted.internet import defer

from synapse.api.errors import RegistrationError
from synapse.handlers.register import RegistrationHandler
from synapse.types import UserID, create_requester

from tests.utils import setup_test_homeserver

from .. import unittest


class RegistrationHandlers(object):
    def __init__(self, hs):
        self.registration_handler = RegistrationHandler(hs)


class RegistrationTestCase(unittest.TestCase):
    """ Tests the RegistrationHandler. """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_distributor = Mock()
        self.mock_distributor.declare("registered_user")
        self.mock_captcha_client = Mock()
        self.hs = yield setup_test_homeserver(
            handlers=None,
            http_client=None,
            expire_access_token=True,
            profile_handler=Mock(),
        )
        self.macaroon_generator = Mock(
            generate_access_token=Mock(return_value='secret'))
        self.hs.get_macaroon_generator = Mock(return_value=self.macaroon_generator)
        self.hs.handlers = RegistrationHandlers(self.hs)
        self.handler = self.hs.get_handlers().registration_handler

    @defer.inlineCallbacks
    def test_user_is_created_and_logged_in_if_doesnt_exist(self):
        local_part = "someone"
        display_name = "someone"
        user_id = "@someone:test"
        requester = create_requester("@as:test")
        result_user_id, result_token = yield self.handler.get_or_create_user(
            requester, local_part, display_name)
        self.assertEquals(result_user_id, user_id)
        self.assertEquals(result_token, 'secret')

    @defer.inlineCallbacks
    def test_if_user_exists(self):
        store = self.hs.get_datastore()
        frank = UserID.from_string("@frank:test")
        yield store.register(
            user_id=frank.to_string(),
            token="jkv;g498752-43gj['eamb!-5",
            password_hash=None)
        local_part = "frank"
        display_name = "Frank"
        user_id = "@frank:test"
        requester = create_requester("@as:test")
        result_user_id, result_token = yield self.handler.get_or_create_user(
            requester, local_part, display_name)
        self.assertEquals(result_user_id, user_id)
        self.assertEquals(result_token, 'secret')

    @defer.inlineCallbacks
    def test_cannot_register_when_mau_limits_exceeded(self):
        local_part = "someone"
        display_name = "someone"
        requester = create_requester("@as:test")
        store = self.hs.get_datastore()
        self.hs.config.limit_usage_by_mau = False
        self.hs.config.max_mau_value = 50
        lots_of_users = 100
        small_number_users = 1

        store.count_monthly_users = Mock(return_value=defer.succeed(lots_of_users))

        # Ensure does not throw exception
        yield self.handler.get_or_create_user(requester, 'a', display_name)

        self.hs.config.limit_usage_by_mau = True

        with self.assertRaises(RegistrationError):
            yield self.handler.get_or_create_user(requester, 'b', display_name)

        store.count_monthly_users = Mock(return_value=defer.succeed(small_number_users))

        self._macaroon_mock_generator("another_secret")

        # Ensure does not throw exception
        yield self.handler.get_or_create_user("@neil:matrix.org", 'c', "Neil")

        self._macaroon_mock_generator("another another secret")
        store.count_monthly_users = Mock(return_value=defer.succeed(lots_of_users))

        with self.assertRaises(RegistrationError):
            yield self.handler.register(localpart=local_part)

        self._macaroon_mock_generator("another another secret")
        store.count_monthly_users = Mock(return_value=defer.succeed(lots_of_users))

        with self.assertRaises(RegistrationError):
            yield self.handler.register_saml2(local_part)

    def _macaroon_mock_generator(self, secret):
        """
        Reset macaroon generator in the case where the test creates multiple users
        """
        macaroon_generator = Mock(
            generate_access_token=Mock(return_value=secret))
        self.hs.get_macaroon_generator = Mock(return_value=macaroon_generator)
        self.hs.handlers = RegistrationHandlers(self.hs)
        self.handler = self.hs.get_handlers().registration_handler
