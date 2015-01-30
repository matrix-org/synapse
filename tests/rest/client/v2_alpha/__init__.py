# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from ....utils import MockHttpResource, MockKey

from synapse.server import HomeServer
from synapse.types import UserID


PATH_PREFIX = "/_matrix/client/v2_alpha"


class V2AlphaRestTestCase(unittest.TestCase):
    # Consumer must define
    #   USER_ID = <some string>
    #   TO_REGISTER = [<list of REST servlets to register>]

    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        mock_config = Mock()
        mock_config.signing_key = [MockKey()]

        hs = HomeServer("test",
            db_pool=None,
            datastore=Mock(spec=[
                "insert_client_ip",
            ]),
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
            config=mock_config,
        )

        def _get_user_by_token(token=None):
            return {
                "user": UserID.from_string(self.USER_ID),
                "admin": False,
                "device_id": None,
            }
        hs.get_auth().get_user_by_token = _get_user_by_token

        for r in self.TO_REGISTER:
            r.register_servlets(hs, self.mock_resource)
