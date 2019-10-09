# -*- coding: utf-8 -*-
# Copyright 2018 Vector Creations Ltd
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
import abc
import logging

from synapse.storage._base import SQLBaseStore

logger = logging.getLogger(__name__)


class StateDeltasStore(SQLBaseStore):
    __metaclass__ = abc.ABCMeta

    def get_current_state_deltas(self, prev_stream_id):
        """Fetch a list of room state changes since the given stream id

        Each entry in the result contains the following fields:
            - stream_id (int)
            - room_id (str)
            - type (str): event type
            - state_key (str):
            - event_id (str|None): new event_id for this state key. None if the
                state has been deleted.
            - prev_event_id (str|None): previous event_id for this state key. None
                if it's new state.

        Args:
            prev_stream_id (int): point to get changes since (exclusive)

        Returns:
            Deferred[tuple[int, list[dict]]: A tuple consisting of:
               - the stream id which these results go up to, or the latest (persisted)
                 room stream ordering
               - list of current_state_delta_stream rows. If it is empty, we are
                 up to date.
        """

        prev_stream_id = int(prev_stream_id)

        # rows are not necessarily persisted to the CSDS table in order. make
        # sure that we only consider stream_ids which have been fully persisted.
        room_max_stream_ordering = self.get_room_max_stream_ordering()

        # check we're not going backwards
        assert prev_stream_id <= room_max_stream_ordering

        if not self._curr_state_delta_stream_cache.has_any_entity_changed(
            prev_stream_id
        ):
            # if the CSDs haven't changed between prev_stream_id and now, we
            # know for certain that they haven't changed between prev_stream_id and
            # room_max_stream_ordering.
            return room_max_stream_ordering, []

        def get_current_state_deltas_txn(txn):
            # First we calculate a max stream id that will give us less than
            # N results.
            # We arbitarily limit to 100 stream_id entries to ensure we don't
            # select toooo many.
            sql = """
                SELECT stream_id, count(*)
                FROM current_state_delta_stream
                WHERE stream_id > ? AND stream_id <= ?
                GROUP BY stream_id
                ORDER BY stream_id ASC
                LIMIT 100
            """
            txn.execute(sql, (prev_stream_id, room_max_stream_ordering))

            total = 0

            # if there are no entries, we may as well go up to the current max stream id
            max_stream_id = room_max_stream_ordering

            for max_stream_id, count in txn:
                total += count
                if total > 100:
                    # We arbitarily limit to 100 entries to ensure we don't
                    # select toooo many.
                    break

            # Now actually get the deltas
            sql = """
                SELECT stream_id, room_id, type, state_key, event_id, prev_event_id
                FROM current_state_delta_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC
            """
            txn.execute(sql, (prev_stream_id, max_stream_id))
            return max_stream_id, self.cursor_to_dict(txn)

        return self.runInteraction(
            "get_current_state_deltas", get_current_state_deltas_txn
        )

    def _get_max_stream_id_in_current_state_deltas_txn(self, txn):
        return self._simple_select_one_onecol_txn(
            txn,
            table="current_state_delta_stream",
            keyvalues={},
            retcol="COALESCE(MAX(stream_id), -1)",
        )

    def get_max_stream_id_in_current_state_deltas(self):
        return self.runInteraction(
            "get_max_stream_id_in_current_state_deltas",
            self._get_max_stream_id_in_current_state_deltas_txn,
        )

    @abc.abstractmethod
    def get_room_max_stream_ordering(self):
        # we expect this to be implemented one way or the other by other classes
        # in the hierarchy
        raise NotImplementedError()
