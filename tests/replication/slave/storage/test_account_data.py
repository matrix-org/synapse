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


from ._base import BaseSlavedStoreTestCase

from synapse.replication.slave.storage.account_data import SlavedAccountDataStore

from twisted.internet import defer

USER_ID = "@feeling:blue"
TYPE = "my.type"


class SlavedAccountDataStoreTestCase(BaseSlavedStoreTestCase):

    STORE_TYPE = SlavedAccountDataStore

    @defer.inlineCallbacks
    def test_user_account_data(self):
        yield self.master_store.add_account_data_for_user(
            USER_ID, TYPE, {"a": 1}
        )
        yield self.replicate()
        yield self.check(
            "get_global_account_data_by_type_for_user",
            [TYPE, USER_ID], {"a": 1}
        )
        yield self.check(
            "get_global_account_data_by_type_for_users",
            [TYPE, [USER_ID]], {USER_ID: {"a": 1}}
        )

        yield self.master_store.add_account_data_for_user(
            USER_ID, TYPE, {"a": 2}
        )
        yield self.replicate()
        yield self.check(
            "get_global_account_data_by_type_for_user",
            [TYPE, USER_ID], {"a": 2}
        )
        yield self.check(
            "get_global_account_data_by_type_for_users",
            [TYPE, [USER_ID]], {USER_ID: {"a": 2}}
        )
