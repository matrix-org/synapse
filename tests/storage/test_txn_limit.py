# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
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


class SQLTransactionLimitTestCase(unittest.HomeserverTestCase):
    """Test SQL transaction limit doesn't break transactions."""

    def make_homeserver(self, reactor, clock):
        return self.setup_test_homeserver(db_txn_limit=1000)

    def test_config(self):
        db_config = self.hs.config.database.get_single_database()
        self.assertEqual(db_config.config["txn_limit"], 1000)

    def test_select(self):
        def do_select(txn):
            txn.execute("SELECT 1")

        db_pool = self.hs.get_datastores().databases[0]

        # force txn limit to roll over at least once
        for _ in range(0, 1001):
            self.get_success_or_raise(db_pool.runInteraction("test_select", do_select))
