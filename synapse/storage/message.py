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
from synapse.api.events.room import MessageEvent

import collections
import json


class MessageStore(SQLBaseStore):

    def get_message(self, user_id, room_id, msg_id):
        """Get a message from the store.

        Args:
            user_id (str): The ID of the user who sent the message.
            room_id (str): The room the message was sent in.
            msg_id (str): The unique ID for this user/room combo.
        """
        query = MessagesTable.select_statement(
            "user_id = ? AND room_id = ? AND msg_id = ? " +
            "ORDER BY id DESC LIMIT 1")
        return self._execute(
            MessagesTable.decode_single_result,
            query, user_id, room_id, msg_id,
        )

    def store_message(self, user_id, room_id, msg_id, content):
        """Store a message in the store.

        Args:
            user_id (str): The ID of the user who sent the message.
            room_id (str): The room the message was sent in.
            msg_id (str): The unique ID for this user/room combo.
            content (str): The content of the message (JSON)
        """
        return self._simple_insert(MessagesTable.table_name, dict(
            user_id=user_id,
            room_id=room_id,
            msg_id=msg_id,
            content=content,
        ))

    def get_max_message_id(self):
        return self._simple_max_id(MessagesTable.table_name)


class MessagesTable(Table):
    table_name = "messages"

    fields = [
        "id",
        "user_id",
        "room_id",
        "msg_id",
        "content"
    ]

    class EntryType(collections.namedtuple("MessageEntry", fields)):

        def as_event(self, event_factory):
            return event_factory.create_event(
                etype=MessageEvent.TYPE,
                room_id=self.room_id,
                user_id=self.user_id,
                msg_id=self.msg_id,
                content=json.loads(self.content),
            )
