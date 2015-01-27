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

from mock import Mock, NonCallableMock
from tests.utils import (
    MockHttpResource, MockClock, DeferredMockCallable, SQLiteMemoryDbPool,
    MockKey
)

from synapse.server import HomeServer


user_localpart = "test_user"

class FilteringTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        self.mock_config = NonCallableMock()
        self.mock_config.signing_key = [MockKey()]

        self.mock_federation_resource = MockHttpResource()

        self.mock_http_client = Mock(spec=[])
        self.mock_http_client.put_json = DeferredMockCallable()

        hs = HomeServer("test",
            db_pool=db_pool,
            handlers=None,
            http_client=self.mock_http_client,
            config=self.mock_config,
            keyring=Mock(),
        )

        self.filtering = hs.get_filtering()

        self.datastore = hs.get_datastore()

    @defer.inlineCallbacks
    def test_add_filter(self):
        filter_id = yield self.filtering.add_user_filter(
            user_localpart=user_localpart,
            definition={"type": ["m.*"]},
        )

        self.assertEquals(filter_id, 0)
        self.assertEquals({"type": ["m.*"]},
            (yield self.datastore.get_user_filter(
                user_localpart=user_localpart,
                filter_id=0,
            ))
        )

    @defer.inlineCallbacks
    def test_get_filter(self):
        filter_id = yield self.datastore.add_user_filter(
            user_localpart=user_localpart,
            definition={"type": ["m.*"]},
        )

        filter = yield self.filtering.get_user_filter(
            user_localpart=user_localpart,
            filter_id=filter_id,
        )

        self.assertEquals(filter, {"type": ["m.*"]})
