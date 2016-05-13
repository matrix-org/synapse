# -*- coding: utf-8 -*-
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

from ._base import BaseSlavedStore
from ._slaved_id_tracker import SlavedIdTracker
from synapse.storage.account_data import AccountDataStore


class SlavedAccountDataStore(BaseSlavedStore):

    def __init__(self, db_conn, hs):
        super(SlavedAccountDataStore, self).__init__(db_conn, hs)
        self._account_data_id_gen = SlavedIdTracker(
            db_conn, "account_data_max_stream_id", "stream_id",
        )

    get_global_account_data_by_type_for_users = (
        AccountDataStore.__dict__["get_global_account_data_by_type_for_users"]
    )

    get_global_account_data_by_type_for_user = (
        AccountDataStore.__dict__["get_global_account_data_by_type_for_user"]
    )

    def stream_positions(self):
        result = super(SlavedAccountDataStore, self).stream_positions()
        position = self._account_data_id_gen.get_current_token()
        result["user_account_data"] = position
        result["room_account_data"] = position
        result["tag_account_data"] = position
        return result

    def process_replication(self, result):
        stream = result.get("user_account_data")
        if stream:
            self._account_data_id_gen.advance(int(stream["position"]))
            for row in stream["rows"]:
                user_id, data_type = row[1:3]
                self.get_global_account_data_by_type_for_user.invalidate(
                    (data_type, user_id,)
                )

        stream = result.get("room_account_data")
        if stream:
            self._account_data_id_gen.advance(int(stream["position"]))

        stream = result.get("tag_account_data")
        if stream:
            self._account_data_id_gen.advance(int(stream["position"]))
