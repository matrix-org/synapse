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

import logging

import six

from synapse.storage._base import _CURRENT_STATE_CACHE_NAME, SQLBaseStore
from synapse.storage.engines import PostgresEngine

from ._slaved_id_tracker import SlavedIdTracker

logger = logging.getLogger(__name__)


def __func__(inp):
    if six.PY3:
        return inp
    else:
        return inp.__func__


class BaseSlavedStore(SQLBaseStore):
    def __init__(self, db_conn, hs):
        super(BaseSlavedStore, self).__init__(db_conn, hs)
        if isinstance(self.database_engine, PostgresEngine):
            self._cache_id_gen = SlavedIdTracker(
                db_conn, "cache_invalidation_stream", "stream_id"
            )
        else:
            self._cache_id_gen = None

        self.hs = hs

    def stream_positions(self):
        pos = {}
        if self._cache_id_gen:
            pos["caches"] = self._cache_id_gen.get_current_token()
        return pos

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "caches":
            self._cache_id_gen.advance(token)
            for row in rows:
                if row.cache_func == _CURRENT_STATE_CACHE_NAME:
                    room_id = row.keys[0]
                    members_changed = set(row.keys[1:])
                    self._invalidate_state_caches(room_id, members_changed)
                else:
                    self._attempt_to_invalidate_cache(row.cache_func, tuple(row.keys))

    def _invalidate_cache_and_stream(self, txn, cache_func, keys):
        txn.call_after(cache_func.invalidate, keys)
        txn.call_after(self._send_invalidation_poke, cache_func, keys)

    def _send_invalidation_poke(self, cache_func, keys):
        self.hs.get_tcp_replication().send_invalidate_cache(cache_func, keys)
