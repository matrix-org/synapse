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

from twisted.internet import defer
from .. import unittest

from synapse.handlers.register import RegistrationHandler

from tests.utils import setup_test_homeserver

from mock import Mock


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
        hs = yield setup_test_homeserver(
            handlers=None,
            http_client=None,
            expire_access_token=True)
        hs.handlers = RegistrationHandlers(hs)
        self.handler = hs.get_handlers().registration_handler
        hs.get_handlers().profile_handler = Mock()
        self.mock_handler = Mock(spec=[
            "generate_short_term_login_token",
        ])

        hs.get_handlers().auth_handler = self.mock_handler

    @defer.inlineCallbacks
    def test_user_is_created_and_logged_in_if_doesnt_exist(self):
        """
        Returns:
            The user doess not exist in this case so it will register and log it in
        """
        duration_ms = 200
        local_part = "someone"
        display_name = "someone"
        user_id = "@someone:test"
        mock_token = self.mock_handler.generate_short_term_login_token
        mock_token.return_value = 'secret'
        result_user_id, result_token = yield self.handler.get_or_create_user(
            local_part, display_name, duration_ms)
        self.assertEquals(result_user_id, user_id)
        self.assertEquals(result_token, 'secret')
