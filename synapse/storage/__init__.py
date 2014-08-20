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
    RoomConfigEvent, RoomNameEvent,
)

from synapse.util.logutils import log_function

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
import logging
import os


logger = logging.getLogger(__name__)


class DataStore(RoomMemberStore, RoomStore,
                RegistrationStore, StreamStore, ProfileStore, FeedbackStore,
                PresenceStore, PduStore, StatePduStore, TransactionStore,
                DirectoryStore):

    def __init__(self, hs):
        super(DataStore, self).__init__(hs)
        self.event_factory = hs.get_event_factory()
        self.hs = hs

        self.min_token_deferred = self._get_min_token()
        self.min_token = None

    @defer.inlineCallbacks
    @log_function
    def persist_event(self, event, backfilled=False):
        if event.type == RoomMemberEvent.TYPE:
            yield self._store_room_member(event)
        elif event.type == FeedbackEvent.TYPE:
            yield self._store_feedback(event)
#        elif event.type == RoomConfigEvent.TYPE:
#            yield self._store_room_config(event)
        elif event.type == RoomNameEvent.TYPE:
            yield self._store_room_name(event)
        elif event.type == RoomTopicEvent.TYPE:
            yield self._store_room_topic(event)

        ret = yield self._store_event(event, backfilled)
        defer.returnValue(ret)

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
    @log_function
    def _store_event(self, event, backfilled):
        # FIXME (erikj): This should be removed when we start amalgamating
        # event and pdu storage
        yield self.hs.get_federation().fill_out_prev_events(event)

        vals = {
            "topological_ordering": event.depth,
            "event_id": event.event_id,
            "type": event.type,
            "room_id": event.room_id,
            "content": json.dumps(event.content),
            "processed": True,
        }

        if backfilled:
            if not self.min_token_deferred.called:
                yield self.min_token_deferred
            self.min_token -= 1
            vals["stream_ordering"] = self.min_token

        unrec = {
            k: v
            for k, v in event.get_full_dict().items()
            if k not in vals.keys()
        }
        vals["unrecognized_keys"] = json.dumps(unrec)

        try:
            yield self._simple_insert("events", vals)
        except:
            logger.exception(
                "Failed to persist, probably duplicate: %s",
                event_id
            )
            return

        if not backfilled and hasattr(event, "state_key"):
            vals = {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "type": event.type,
                "state_key": event.state_key,
            }

            if hasattr(event, "prev_state"):
                vals["prev_state"] = event.prev_state

            yield self._simple_insert("state_events", vals)

            yield self._simple_insert(
                "current_state_events",
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "type": event.type,
                    "state_key": event.state_key,
                }
            )

        latest = yield self.get_room_events_max_id()
        defer.returnValue(latest)

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

    @defer.inlineCallbacks
    def _get_min_token(self):
        row = yield self._execute(
            None,
            "SELECT MIN(stream_ordering) FROM events"
        )

        self.min_token = row[0][0] if row and row[0] and row[0][0] else -1
        self.min_token = min(self.min_token, -1)

        logger.debug("min_token is: %s", self.min_token)

        defer.returnValue(self.min_token)


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
