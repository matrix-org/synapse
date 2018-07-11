# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""Tests REST events for /admin paths."""
from mock import Mock
from twisted.internet import defer

import synapse.types
from synapse.api.errors import SynapseError, AuthError
from synapse.rest.client.v1 import admin
from tests import unittest
from ....utils import MockHttpResource, setup_test_homeserver

ID = "@1234ABCD:test"
ADMIN_ID = "@5678EFGH:test"
PATH_PREFIX = "/_matrix/client/api/v1"
MAU_COUNT = 36
MAU_MAX = 50
LIMIT_MAU = True


class AdminTestCase(unittest.TestCase):
    """ Tests Admin tools. """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.mock_handler = Mock(spec=[
            "get_server_metrics",
        ])

        hs = yield setup_test_homeserver(
            "test",
            http_client=None,
            resource_for_client=self.mock_resource,
            federation=Mock(),
            federation_client=Mock(),
            admin_handler=self.mock_handler
        )

        def _get_user_by_req(request=None, allow_guest=False):
            return synapse.types.create_requester(request.args['user_id'])

        def _is_server_admin(user):
            if str(user) == ADMIN_ID:
                return True
            else:
                return False

        def _count_monthly_users():
            return MAU_COUNT

        hs.get_auth().get_user_by_req = _get_user_by_req
        hs.get_auth().is_server_admin = _is_server_admin
        hs.get_datastore().count_monthly_users = _count_monthly_users
        hs.config.media_storage_providers = []
        hs.config.default_max_mau = MAU_MAX
        hs.config.limit_mau = LIMIT_MAU

        admin.register_servlets(hs, self.mock_resource)

    @defer.inlineCallbacks
    def test_get_server_metrics(self):
        mocked_get = self.mock_handler.get_server_metrics

        mock_request = Mock(args={'user_id': ID})
        request = '{"user_id": %s}' % (ID,)
        (code, response) = yield self.mock_resource.trigger(
            "GET", "/admin/server_metrics", None, mock_request
        )
        self.assertEquals(403, code)

        mock_request = Mock(args={"user_id": ADMIN_ID})
        (code, response) = yield self.mock_resource.trigger(
            "GET", "/admin/server_metrics", None, mock_request
        )

        self.assertEquals(200, code)
        self.assertEquals(
            {
                "limit_mau_enabled": LIMIT_MAU,
                "max_mau": MAU_MAX,
                "mau": MAU_COUNT
            },
            response
        )
