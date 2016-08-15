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

from synapse.storage._base import SQLBaseStore
from synapse.storage.engines import PostgresEngine
from twisted.internet import defer

from ._slaved_id_tracker import SlavedIdTracker

import logging

logger = logging.getLogger(__name__)


class BaseSlavedStore(SQLBaseStore):
    def __init__(self, db_conn, hs):
        super(BaseSlavedStore, self).__init__(hs)
        if isinstance(self.database_engine, PostgresEngine):
            self._cache_id_gen = SlavedIdTracker(
                db_conn, "cache_invalidation_stream", "stream_id",
            )
        else:
            self._cache_id_gen = None

    def stream_positions(self):
        pos = {}
        if self._cache_id_gen:
            pos["caches"] = self._cache_id_gen.get_current_token()
        return pos

    def process_replication(self, result):
        stream = result.get("caches")
        if stream:
            for row in stream["rows"]:
                (
                    position, cache_func, keys, invalidation_ts,
                ) = row

                try:
                    getattr(self, cache_func).invalidate(tuple(keys))
                except AttributeError:
                    logger.info("Got unexpected cache_func: %r", cache_func)
            self._cache_id_gen.advance(int(stream["position"]))
        return defer.succeed(None)
