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

from synapse.replication.slave.storage._slaved_id_tracker import SlavedIdTracker
from synapse.replication.tcp.streams import PushRulesStream
from synapse.storage.databases.main.push_rule import PushRulesWorkerStore

from .events import SlavedEventStore


class SlavedPushRuleStore(SlavedEventStore, PushRulesWorkerStore):
    def get_max_push_rules_stream_id(self):
        return self._push_rules_stream_id_gen.get_current_token()

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        # We assert this for the benefit of mypy
        assert isinstance(self._push_rules_stream_id_gen, SlavedIdTracker)

        if stream_name == PushRulesStream.NAME:
            self._push_rules_stream_id_gen.advance(instance_name, token)
            for row in rows:
                self.get_push_rules_for_user.invalidate((row.user_id,))
                self.get_push_rules_enabled_for_user.invalidate((row.user_id,))
                self.push_rules_stream_cache.entity_has_changed(row.user_id, token)
        return super().process_replication_rows(stream_name, instance_name, token, rows)
