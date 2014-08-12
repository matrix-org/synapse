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

from synapse.api.events.room import (
    RoomMemberEvent, MessageEvent, RoomTopicEvent, FeedbackEvent,
    RoomConfigEvent
)

from .directory import DirectoryStore
from .feedback import FeedbackStore
from .message import MessageStore
from .presence import PresenceStore
from .profile import ProfileStore
from .registration import RegistrationStore
from .room import RoomStore
from .roommember import RoomMemberStore
from .roomdata import RoomDataStore
from .stream import StreamStore
from .pdu import StatePduStore, PduStore
from .transactions import TransactionStore

import json
import os


class DataStore(RoomDataStore, RoomMemberStore, MessageStore, RoomStore,
                RegistrationStore, StreamStore, ProfileStore, FeedbackStore,
                PresenceStore, PduStore, StatePduStore, TransactionStore,
                DirectoryStore):

    def __init__(self, hs):
        super(DataStore, self).__init__(hs)
        self.event_factory = hs.get_event_factory()
        self.hs = hs

    def persist_event(self, event):
        if event.type == MessageEvent.TYPE:
            return self.store_message(
                user_id=event.user_id,
                room_id=event.room_id,
                msg_id=event.msg_id,
                content=json.dumps(event.content)
            )
        elif event.type == RoomMemberEvent.TYPE:
            return self.store_room_member(
                user_id=event.target_user_id,
                sender=event.user_id,
                room_id=event.room_id,
                content=event.content,
                membership=event.content["membership"]
            )
        elif event.type == FeedbackEvent.TYPE:
            return self.store_feedback(
                room_id=event.room_id,
                msg_id=event.msg_id,
                msg_sender_id=event.msg_sender_id,
                fb_sender_id=event.user_id,
                fb_type=event.feedback_type,
                content=json.dumps(event.content)
            )
        elif event.type == RoomTopicEvent.TYPE:
            return self.store_room_data(
                room_id=event.room_id,
                etype=event.type,
                state_key=event.state_key,
                content=json.dumps(event.content)
            )
        elif event.type == RoomConfigEvent.TYPE:
            if "visibility" in event.content:
                visibility = event.content["visibility"]
                return self.store_room_config(
                    room_id=event.room_id,
                    visibility=visibility
                )

        else:
            raise NotImplementedError(
                "Don't know how to persist type=%s" % event.type
            )


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
