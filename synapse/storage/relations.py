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

import attr

from synapse.api.constants import RelationTypes
from synapse.storage._base import SQLBaseStore

logger = logging.getLogger(__name__)


@attr.s
class PaginationChunk(object):
    """Returned by relation pagination APIs.

    Attributes:
        chunk (list): The rows returned by pagination
    """

    chunk = attr.ib()

    def to_dict(self):
        d = {"chunk": self.chunk}

        return d


class RelationsStore(SQLBaseStore):
    def get_relations_for_event(
        self, event_id, relation_type=None, event_type=None, limit=5, direction="b"
    ):
        """Get a list of relations for an event, ordered by topological ordering.

        Args:
            event_id (str): Fetch events that relate to this event ID.
            relation_type (str|None): Only fetch events with this relation
                type, if given.
            event_type (str|None): Only fetch events with this event type, if
                given.
            limit (int): Only fetch the most recent `limit` events.
            direction (str): Whether to fetch the most recent first (`"b"`) or
                the oldest first (`"f"`).

        Returns:
            Deferred[PaginationChunk]: List of event IDs that match relations
            requested. The rows are of the form `{"event_id": "..."}`.
        """

        # TODO: Pagination tokens

        where_clause = ["relates_to_id = ?"]
        where_args = [event_id]

        if relation_type is not None:
            where_clause.append("relation_type = ?")
            where_args.append(relation_type)

        if event_type is not None:
            where_clause.append("type = ?")
            where_args.append(event_type)

        order = "ASC"
        if direction == "b":
            order = "DESC"

        sql = """
            SELECT event_id FROM event_relations
            INNER JOIN events USING (event_id)
            WHERE %s
            ORDER BY topological_ordering %s, stream_ordering %s
            LIMIT ?
        """ % (
            " AND ".join(where_clause),
            order,
            order,
        )

        def _get_recent_references_for_event_txn(txn):
            txn.execute(sql, where_args + [limit + 1])

            events = [{"event_id": row[0]} for row in txn]

            return PaginationChunk(
                chunk=list(events[:limit]),
            )

        return self.runInteraction(
            "get_recent_references_for_event", _get_recent_references_for_event_txn
        )

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
