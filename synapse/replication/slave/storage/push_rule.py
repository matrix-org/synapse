# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from .events import SlavedEventStore
from ._slaved_id_tracker import SlavedIdTracker
from synapse.storage import DataStore
from synapse.storage.push_rule import PushRuleStore
from synapse.util.caches.stream_change_cache import StreamChangeCache


class SlavedPushRuleStore(SlavedEventStore):
    def __init__(self, db_conn, hs):
        super(SlavedPushRuleStore, self).__init__(db_conn, hs)
        self._push_rules_stream_id_gen = SlavedIdTracker(
            db_conn, "push_rules_stream", "stream_id",
        )
        self.push_rules_stream_cache = StreamChangeCache(
            "PushRulesStreamChangeCache",
            self._push_rules_stream_id_gen.get_current_token(),
        )

    get_push_rules_for_user = PushRuleStore.__dict__["get_push_rules_for_user"]
    get_push_rules_enabled_for_user = (
        PushRuleStore.__dict__["get_push_rules_enabled_for_user"]
    )
    have_push_rules_changed_for_user = (
        DataStore.have_push_rules_changed_for_user.__func__
    )

    def get_push_rules_stream_token(self):
        return (
            self._push_rules_stream_id_gen.get_current_token(),
            self._stream_id_gen.get_current_token(),
        )

    def stream_positions(self):
        result = super(SlavedPushRuleStore, self).stream_positions()
        result["push_rules"] = self._push_rules_stream_id_gen.get_current_token()
        return result

    def process_replication(self, result):
        stream = result.get("push_rules")
        if stream:
            for row in stream["rows"]:
                position = row[0]
                user_id = row[2]
                self.get_push_rules_for_user.invalidate((user_id,))
                self.get_push_rules_enabled_for_user.invalidate((user_id,))
                self.push_rules_stream_cache.entity_has_changed(
                    user_id, position
                )

            self._push_rules_stream_id_gen.advance(int(stream["position"]))

        return super(SlavedPushRuleStore, self).process_replication(result)
