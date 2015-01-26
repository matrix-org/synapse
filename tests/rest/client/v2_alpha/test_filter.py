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
from twisted.internet import defer

from mock import Mock

from ....utils import MockHttpResource, MockKey

from synapse.server import HomeServer
from synapse.rest.client.v2_alpha import filter
from synapse.types import UserID


myid = "@apple:test"
PATH_PREFIX = "/_matrix/client/v2_alpha"


class FilterTestCase(unittest.TestCase):

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
                "user": UserID.from_string(myid),
                "admin": False,
                "device_id": None,
            }
        hs.get_auth().get_user_by_token = _get_user_by_token

        filter.register_servlets(hs, self.mock_resource)

    @defer.inlineCallbacks
    def test_filter(self):
        (code, response) = yield self.mock_resource.trigger("POST",
            "/user/%s/filter" % (myid),
            '{"type": ["m.*"]}'
        )
        self.assertEquals(200, code)
        self.assertEquals({"filter_id": "0"}, response)

        (code, response) = yield self.mock_resource.trigger("GET",
            "/user/%s/filter/0" % (myid), None
        )
        self.assertEquals(200, code)
        self.assertEquals({"type": ["m.*"]}, response)
