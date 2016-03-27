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

from tests import unittest

from mock import Mock

from ....utils import MockHttpResource, setup_test_homeserver

from synapse.types import UserID

from twisted.internet import defer


PATH_PREFIX = "/_matrix/client/v2_alpha"


class V2AlphaRestTestCase(unittest.TestCase):
    # Consumer must define
    #   USER_ID = <some string>
    #   TO_REGISTER = [<list of REST servlets to register>]

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = yield setup_test_homeserver(
            datastore=self.make_datastore_mock(),
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
        )

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.USER_ID),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_auth().get_user_by_access_token = get_user_by_access_token

        for r in self.TO_REGISTER:
            r.register_servlets(hs, self.mock_resource)

    def make_datastore_mock(self):
        store = Mock(spec=[
            "insert_client_ip",
        ])
        store.get_app_service_by_token = Mock(return_value=None)
        return store
