# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.storage.push_rule import PushRulesWorkerStore

from ._slaved_id_tracker import SlavedIdTracker
from .events import SlavedEventStore


class SlavedPushRuleStore(PushRulesWorkerStore, SlavedEventStore):
    def __init__(self, db_conn, hs):
        self._push_rules_stream_id_gen = SlavedIdTracker(
            db_conn, "push_rules_stream", "stream_id",
        )
        super(SlavedPushRuleStore, self).__init__(db_conn, hs)

    def get_push_rules_stream_token(self):
        return (
            self._push_rules_stream_id_gen.get_current_token(),
            self._stream_id_gen.get_current_token(),
        )

    def get_max_push_rules_stream_id(self):
        return self._push_rules_stream_id_gen.get_current_token()

    def stream_positions(self):
        result = super(SlavedPushRuleStore, self).stream_positions()
        result["push_rules"] = self._push_rules_stream_id_gen.get_current_token()
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "push_rules":
            self._push_rules_stream_id_gen.advance(token)
            for row in rows:
                self.get_push_rules_for_user.invalidate((row.user_id,))
                self.get_push_rules_enabled_for_user.invalidate((row.user_id,))
                self.push_rules_stream_cache.entity_has_changed(
                    row.user_id, token
                )
        return super(SlavedPushRuleStore, self).process_replication_rows(
            stream_name, token, rows
        )
