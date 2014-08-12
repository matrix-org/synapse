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
from twisted.internet import defer

from sqlite3 import IntegrityError

from synapse.api.errors import StoreError
from synapse.api.events.room import RoomTopicEvent

from ._base import SQLBaseStore, Table

import collections
import json
import logging

logger = logging.getLogger(__name__)


class RoomStore(SQLBaseStore):

    @defer.inlineCallbacks
    def store_room(self, room_id, room_creator_user_id, is_public):
        """Stores a room.

        Args:
            room_id (str): The desired room ID, can be None.
            room_creator_user_id (str): The user ID of the room creator.
            is_public (bool): True to indicate that this room should appear in
            public room lists.
        Raises:
            StoreError if the room could not be stored.
        """
        try:
            yield self._simple_insert(RoomsTable.table_name, dict(
                room_id=room_id,
                creator=room_creator_user_id,
                is_public=is_public
            ))
        except IntegrityError:
            raise StoreError(409, "Room ID in use.")
        except Exception as e:
            logger.error("store_room with room_id=%s failed: %s", room_id, e)
            raise StoreError(500, "Problem creating room.")

    def store_room_config(self, room_id, visibility):
        return self._simple_update_one(
            table=RoomsTable.table_name,
            keyvalues={"room_id": room_id},
            updatevalues={"is_public": visibility}
        )

    def get_room(self, room_id):
        """Retrieve a room.

        Args:
            room_id (str): The ID of the room to retrieve.
        Returns:
            A namedtuple containing the room information, or an empty list.
        """
        query = RoomsTable.select_statement("room_id=?")
        return self._execute(
            RoomsTable.decode_single_result, query, room_id,
        )

    @defer.inlineCallbacks
    def get_rooms(self, is_public, with_topics):
        """Retrieve a list of all public rooms.

        Args:
            is_public (bool): True if the rooms returned should be public.
            with_topics (bool): True to include the current topic for the room
            in the response.
        Returns:
            A list of room dicts containing at least a "room_id" key, and a
            "topic" key if one is set and with_topic=True.
        """
        room_data_type = RoomTopicEvent.TYPE
        public = 1 if is_public else 0

        latest_topic = ("SELECT max(room_data.id) FROM room_data WHERE "
                        + "room_data.type = ? GROUP BY room_id")

        query = ("SELECT rooms.*, room_data.content FROM rooms LEFT JOIN "
                 + "room_data ON rooms.room_id = room_data.room_id WHERE "
                 + "(room_data.id IN (" + latest_topic + ") "
                 + "OR room_data.id IS NULL) AND rooms.is_public = ?")

        res = yield self._execute(
            self.cursor_to_dict, query, room_data_type, public
        )

        # return only the keys the specification expects
        ret_keys = ["room_id", "topic"]

        # extract topic from the json (icky) FIXME
        for i, room_row in enumerate(res):
            try:
                content_json = json.loads(room_row["content"])
                room_row["topic"] = content_json["topic"]
            except:
                pass  # no topic set
            # filter the dict based on ret_keys
            res[i] = {k: v for k, v in room_row.iteritems() if k in ret_keys}

        defer.returnValue(res)


class RoomsTable(Table):
    table_name = "rooms"

    fields = [
        "room_id",
        "is_public",
        "creator"
    ]

    EntryType = collections.namedtuple("RoomEntry", fields)
