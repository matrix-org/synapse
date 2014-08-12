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
from synapse.api.events.room import FeedbackEvent

import collections
import json


class FeedbackStore(SQLBaseStore):

    def store_feedback(self, room_id, msg_id, msg_sender_id,
                       fb_sender_id, fb_type, content):
        return self._simple_insert(FeedbackTable.table_name, dict(
            room_id=room_id,
            msg_id=msg_id,
            msg_sender_id=msg_sender_id,
            fb_sender_id=fb_sender_id,
            fb_type=fb_type,
            content=content,
        ))

    def get_feedback(self, room_id=None, msg_id=None, msg_sender_id=None,
                     fb_sender_id=None, fb_type=None):
        query = FeedbackTable.select_statement(
            "msg_sender_id = ? AND room_id = ? AND msg_id = ? " +
            "AND fb_sender_id = ? AND feedback_type = ? " +
            "ORDER BY id DESC LIMIT 1")
        return self._execute(
            FeedbackTable.decode_single_result,
            query, msg_sender_id, room_id, msg_id, fb_sender_id, fb_type,
        )

    def get_max_feedback_id(self):
        return self._simple_max_id(FeedbackTable.table_name)


class FeedbackTable(Table):
    table_name = "feedback"

    fields = [
        "id",
        "content",
        "feedback_type",
        "fb_sender_id",
        "msg_id",
        "room_id",
        "msg_sender_id"
    ]

    class EntryType(collections.namedtuple("FeedbackEntry", fields)):

        def as_event(self, event_factory):
            return event_factory.create_event(
                etype=FeedbackEvent.TYPE,
                room_id=self.room_id,
                msg_id=self.msg_id,
                msg_sender_id=self.msg_sender_id,
                user_id=self.fb_sender_id,
                feedback_type=self.feedback_type,
                content=json.loads(self.content),
            )
