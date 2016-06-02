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
from synapse.storage import DataStore
from synapse.storage.account_data import AccountDataStore
from synapse.storage.tags import TagsStore
from synapse.util.caches.stream_change_cache import StreamChangeCache


class SlavedAccountDataStore(BaseSlavedStore):

    def __init__(self, db_conn, hs):
        super(SlavedAccountDataStore, self).__init__(db_conn, hs)
        self._account_data_id_gen = SlavedIdTracker(
            db_conn, "account_data_max_stream_id", "stream_id",
        )
        self._account_data_stream_cache = StreamChangeCache(
            "AccountDataAndTagsChangeCache",
            self._account_data_id_gen.get_current_token(),
        )

    get_account_data_for_user = (
        AccountDataStore.__dict__["get_account_data_for_user"]
    )

    get_global_account_data_by_type_for_users = (
        AccountDataStore.__dict__["get_global_account_data_by_type_for_users"]
    )

    get_global_account_data_by_type_for_user = (
        AccountDataStore.__dict__["get_global_account_data_by_type_for_user"]
    )

    get_tags_for_user = TagsStore.__dict__["get_tags_for_user"]

    get_updated_tags = DataStore.get_updated_tags.__func__
    get_updated_account_data_for_user = (
        DataStore.get_updated_account_data_for_user.__func__
    )

    def get_max_account_data_stream_id(self):
        return self._account_data_id_gen.get_current_token()

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
                position, user_id, data_type = row[:3]
                self.get_global_account_data_by_type_for_user.invalidate(
                    (data_type, user_id,)
                )
                self.get_account_data_for_user.invalidate((user_id,))
                self._account_data_stream_cache.entity_has_changed(
                    user_id, position
                )

        stream = result.get("room_account_data")
        if stream:
            self._account_data_id_gen.advance(int(stream["position"]))
            for row in stream["rows"]:
                position, user_id = row[:2]
                self.get_account_data_for_user.invalidate((user_id,))
                self._account_data_stream_cache.entity_has_changed(
                    user_id, position
                )

        stream = result.get("tag_account_data")
        if stream:
            self._account_data_id_gen.advance(int(stream["position"]))
            for row in stream["rows"]:
                position, user_id = row[:2]
                self.get_tags_for_user.invalidate((user_id,))
                self._account_data_stream_cache.entity_has_changed(
                    user_id, position
                )

        return super(SlavedAccountDataStore, self).process_replication(result)
