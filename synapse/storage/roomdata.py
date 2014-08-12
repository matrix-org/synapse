# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from ._base import SQLBaseStore, Table

import collections
import json


class RoomDataStore(SQLBaseStore):

    """Provides various CRUD operations for Room Events. """

    def get_room_data(self, room_id, etype, state_key=""):
        """Retrieve the data stored under this type and state_key.

        Args:
            room_id (str)
            etype (str)
            state_key (str)
        Returns:
            namedtuple: Or None if nothing exists at this path.
        """
        query = RoomDataTable.select_statement(
            "room_id = ? AND type = ? AND state_key = ? "
            "ORDER BY id DESC LIMIT 1"
        )
        return self._execute(
            RoomDataTable.decode_single_result,
            query, room_id, etype, state_key,
        )

    def store_room_data(self, room_id, etype, state_key="", content=None):
        """Stores room specific data.

        Args:
            room_id (str)
            etype (str)
            state_key (str)
            data (str)- The data to store for this path in JSON.
        Returns:
            The store ID for this data.
        """
        return self._simple_insert(RoomDataTable.table_name, dict(
            etype=etype,
            state_key=state_key,
            room_id=room_id,
            content=content,
        ))

    def get_max_room_data_id(self):
        return self._simple_max_id(RoomDataTable.table_name)


class RoomDataTable(Table):
    table_name = "room_data"

    fields = [
        "id",
        "room_id",
        "type",
        "state_key",
        "content"
    ]

    class EntryType(collections.namedtuple("RoomDataEntry", fields)):

        def as_event(self, event_factory):
            return event_factory.create_event(
                etype=self.type,
                room_id=self.room_id,
                content=json.loads(self.content),
            )
