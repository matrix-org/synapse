# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from tests.replication._base import BaseStreamTestCase


class BaseSlavedStoreTestCase(BaseStreamTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(federation_client=Mock())

        return hs

    def prepare(self, reactor, clock, hs):
        super().prepare(reactor, clock, hs)

        self.reconnect()

        self.master_store = hs.get_datastore()
        self.slaved_store = self.worker_hs.get_datastore()
        self.storage = hs.get_storage()

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump(0.1)

    def check(self, method, args, expected_result=None):
        master_result = self.get_success(getattr(self.master_store, method)(*args))
        slaved_result = self.get_success(getattr(self.slaved_store, method)(*args))
        if expected_result is not None:
            self.assertEqual(
                master_result,
                expected_result,
                "Expected master result to be %r but was %r"
                % (expected_result, master_result),
            )
            self.assertEqual(
                slaved_result,
                expected_result,
                "Expected slave result to be %r but was %r"
                % (expected_result, slaved_result),
            )
        self.assertEqual(
            master_result,
            slaved_result,
            "Slave result %r does not match master result %r"
            % (slaved_result, master_result),
        )
