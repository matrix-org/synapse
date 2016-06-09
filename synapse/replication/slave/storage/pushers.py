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


class SlavedPusherStore(BaseSlavedStore):

    def __init__(self, db_conn, hs):
        super(SlavedPusherStore, self).__init__(db_conn, hs)
        self._pushers_id_gen = SlavedIdTracker(
            db_conn, "pushers", "id",
            extra_tables=[("deleted_pushers", "stream_id")],
        )

    get_all_pushers = DataStore.get_all_pushers.__func__
    get_pushers_by = DataStore.get_pushers_by.__func__
    get_pushers_by_app_id_and_pushkey = (
        DataStore.get_pushers_by_app_id_and_pushkey.__func__
    )
    _decode_pushers_rows = DataStore._decode_pushers_rows.__func__

    def stream_positions(self):
        result = super(SlavedPusherStore, self).stream_positions()
        result["pushers"] = self._pushers_id_gen.get_current_token()
        return result

    def process_replication(self, result):
        stream = result.get("pushers")
        if stream:
            self._pushers_id_gen.advance(int(stream["position"]))

        stream = result.get("deleted_pushers")
        if stream:
            self._pushers_id_gen.advance(int(stream["position"]))

        return super(SlavedPusherStore, self).process_replication(result)
