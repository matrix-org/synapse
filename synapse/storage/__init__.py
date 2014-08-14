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

from synapse.api.events.room import (
    RoomMemberEvent, MessageEvent, RoomTopicEvent, FeedbackEvent,
    RoomConfigEvent
)

from .directory import DirectoryStore
from .feedback import FeedbackStore
from .presence import PresenceStore
from .profile import ProfileStore
from .registration import RegistrationStore
from .room import RoomStore
from .roommember import RoomMemberStore
from .stream import StreamStore
from .pdu import StatePduStore, PduStore
from .transactions import TransactionStore

import json
import os


class DataStore(RoomMemberStore, RoomStore,
                RegistrationStore, StreamStore, ProfileStore, FeedbackStore,
                PresenceStore, PduStore, StatePduStore, TransactionStore,
                DirectoryStore):

    def __init__(self, hs):
        super(DataStore, self).__init__(hs)
        self.event_factory = hs.get_event_factory()

    @defer.inlineCallbacks
    def persist_event(self, event):
        if event.type == RoomMemberEvent.TYPE:
            yield self._store_room_member(event)
        elif event.type == FeedbackEvent.TYPE:
            yield self._store_feedback(event)
        elif event.type == RoomConfigEvent.TYPE:
            yield self._store_room_config(event)

        yield self._store_event(event)

    @defer.inlineCallbacks
    def get_event(self, event_id):
        events_dict = yield self._simple_select_one(
            "events",
            {"event_id": event_id},
            [
                "event_id",
                "type",
                "sender",
                "room_id",
                "content",
                "unrecognized_keys"
            ],
        )

        event = self._parse_event_from_row(events_dict)
        defer.returnValue(event)

    @defer.inlineCallbacks
    def _store_event(self, event):
        vals = {
            "event_id": event.event_id,
            "type": event.type,
            "room_id": event.room_id,
            "content": json.dumps(event.content),
        }

        unrec = {k: v for k, v in event.get_full_dict().items() if k not in vals.keys()}
        vals["unrecognized_keys"] = json.dumps(unrec)

        yield self._simple_insert("events", vals)

        if hasattr(event, "state_key"):
            vals = {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "type": event.type,
                "state_key": event.state_key,
            }

            if hasattr(event, "prev_state"):
                vals["prev_state"] = event.prev_state

            yield self._simple_insert("state_events", vals)

            # TODO (erikj): We also need to update the current state table?

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key=""):
        sql = (
            "SELECT e.* FROM events as e "
            "INNER JOIN current_state_events as c ON e.event_id = c.event_id "
            "INNER JOIN state_events as s ON e.event_id = s.event_id "
            "WHERE c.room_id = ? "
        )

        if event_type:
            sql += " AND s.type = ? AND s.state_key = ? "
            args = (room_id, event_type, state_key)
        else:
            args = (room_id, )

        results = yield self._execute_and_decode(sql, *args)

        defer.returnValue([self._parse_event_from_row(r) for r in results])


def schema_path(schema):
    """ Get a filesystem path for the named database schema

    Args:
        schema: Name of the database schema.
    Returns:
        A filesystem path pointing at a ".sql" file.

    """
    dir_path = os.path.dirname(__file__)
    schemaPath = os.path.join(dir_path, "schema", schema + ".sql")
    return schemaPath


def read_schema(schema):
    """ Read the named database schema.

    Args:
        schema: Name of the datbase schema.
    Returns:
        A string containing the database schema.
    """
    with open(schema_path(schema)) as schema_file:
        return schema_file.read()
