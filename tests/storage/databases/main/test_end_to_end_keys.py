# Copyright 2023 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class EndToEndKeyWorkerStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def test_get_master_cross_signing_key_updatable_before(self) -> None:
        # Should return False, None when there is no master key.
        alice = "@alice:test"
        exists, timestamp = self.get_success(
            self.store.get_master_cross_signing_key_updatable_before(alice)
        )
        self.assertIs(exists, False)
        self.assertIsNone(timestamp)

        # Upload a master key.
        dummy_key = {"keys": {"a": "b"}}
        self.get_success(
            self.store.set_e2e_cross_signing_key("@alice:test", "master", dummy_key)
        )

        # Should now find that the key exists.
        exists, timestamp = self.get_success(
            self.store.get_master_cross_signing_key_updatable_before(alice)
        )
        self.assertIs(exists, True)
        self.assertIsNone(timestamp)

        # Write an updateable_before timestamp.
        written_timestamp = 123456789
        self.get_success(
            self.store.db_pool.simple_update_one(
                "e2e_cross_signing_keys",
                {"user_id": alice, "keytype": "master"},
                {"updatable_without_uia_before_ms": written_timestamp},
            )
        )

        # Should now find that the key exists.
        exists, timestamp = self.get_success(
            self.store.get_master_cross_signing_key_updatable_before(alice)
        )
        self.assertIs(exists, True)
        self.assertEqual(timestamp, written_timestamp)
