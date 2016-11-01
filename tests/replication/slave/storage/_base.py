# Copyright 2016 OpenMarket Ltd
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
from tests import unittest

from mock import Mock, NonCallableMock
from tests.utils import setup_test_homeserver
from synapse.replication.resource import ReplicationResource


class BaseSlavedStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(
            "blue",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.hs.get_ratelimiter().send_message.return_value = (True, 0)

        self.replication = ReplicationResource(self.hs)

        self.master_store = self.hs.get_datastore()
        self.slaved_store = self.STORE_TYPE(self.hs.get_db_conn(), self.hs)
        self.event_id = 0

    @defer.inlineCallbacks
    def replicate(self):
        streams = self.slaved_store.stream_positions()
        writer = yield self.replication.replicate(streams, 100)
        result = writer.finish()
        yield self.slaved_store.process_replication(result)

    @defer.inlineCallbacks
    def check(self, method, args, expected_result=None):
        master_result = yield getattr(self.master_store, method)(*args)
        slaved_result = yield getattr(self.slaved_store, method)(*args)
        if expected_result is not None:
            self.assertEqual(master_result, expected_result)
            self.assertEqual(slaved_result, expected_result)
        self.assertEqual(master_result, slaved_result)
