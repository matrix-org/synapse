# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from synapse.api.constants import RelationTypes
from synapse.storage._base import SQLBaseStore

logger = logging.getLogger(__name__)


class RelationsStore(SQLBaseStore):
    def _handle_event_relations(self, txn, event):
        """Handles inserting relation data during peristence of events

        Args:
            txn
            event (EventBase)
        """
        relation = event.content.get("m.relates_to")
        if not relation:
            # No relations
            return

        rel_type = relation.get("rel_type")
        if rel_type not in (
            RelationTypes.ANNOTATION,
            RelationTypes.REFERENCES,
            RelationTypes.REPLACES,
        ):
            # Unknown relation type
            return

        parent_id = relation.get("event_id")
        if not parent_id:
            # Invalid relation
            return

        aggregation_key = relation.get("key")

        self._simple_insert_txn(
            txn,
            table="event_relations",
            values={
                "event_id": event.event_id,
                "relates_to_id": parent_id,
                "relation_type": rel_type,
                "aggregation_key": aggregation_key,
            },
        )
