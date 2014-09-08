# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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
    RoomMemberEvent, RoomTopicEvent, FeedbackEvent,
#   RoomConfigEvent,
    RoomNameEvent,
    RoomJoinRulesEvent,
    RoomPowerLevelsEvent,
    RoomAddStateLevelEvent,
    RoomSendEventLevelEvent,
    RoomOpsPowerLevelsEvent,
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
from .keys import KeyStore

import json
import logging
import os


logger = logging.getLogger(__name__)


class DataStore(RoomMemberStore, RoomStore,
                RegistrationStore, StreamStore, ProfileStore, FeedbackStore,
                PresenceStore, PduStore, StatePduStore, TransactionStore,
                DirectoryStore, KeyStore):

    def __init__(self, hs):
        super(DataStore, self).__init__(hs)
        self.event_factory = hs.get_event_factory()
        self.hs = hs

        self.min_token_deferred = self._get_min_token()
        self.min_token = None

    @defer.inlineCallbacks
    @log_function
    def persist_event(self, event=None, backfilled=False, pdu=None):
        stream_ordering = None
        if backfilled:
            if not self.min_token_deferred.called:
                yield self.min_token_deferred
            self.min_token -= 1
            stream_ordering = self.min_token

        latest = yield self._db_pool.runInteraction(
            self._persist_pdu_event_txn,
            pdu=pdu,
            event=event,
            backfilled=backfilled,
            stream_ordering=stream_ordering,
        )
        defer.returnValue(latest)

    @defer.inlineCallbacks
    def get_event(self, event_id, allow_none=False):
        events_dict = yield self._simple_select_one(
            "events",
            {"event_id": event_id},
            [
                "event_id",
                "type",
                "room_id",
                "content",
                "unrecognized_keys"
            ],
            allow_none=allow_none,
        )

        if not events_dict:
            defer.returnValue(None)

        event = self._parse_event_from_row(events_dict)
        defer.returnValue(event)

    def _persist_pdu_event_txn(self, txn, pdu=None, event=None,
                               backfilled=False, stream_ordering=None):
        if pdu is not None:
            self._persist_event_pdu_txn(txn, pdu)
        if event is not None:
            return self._persist_event_txn(
                txn, event, backfilled, stream_ordering
            )

    def _persist_event_pdu_txn(self, txn, pdu):
        cols = dict(pdu.__dict__)
        unrec_keys = dict(pdu.unrecognized_keys)
        del cols["content"]
        del cols["prev_pdus"]
        cols["content_json"] = json.dumps(pdu.content)
        cols["unrecognized_keys"] = json.dumps(unrec_keys)

        logger.debug("Persisting: %s", repr(cols))

        if pdu.is_state:
            self._persist_state_txn(txn, pdu.prev_pdus, cols)
        else:
            self._persist_pdu_txn(txn, pdu.prev_pdus, cols)

        self._update_min_depth_for_context_txn(txn, pdu.context, pdu.depth)

    @log_function
    def _persist_event_txn(self, txn, event, backfilled, stream_ordering=None):
        if event.type == RoomMemberEvent.TYPE:
            self._store_room_member_txn(txn, event)
        elif event.type == FeedbackEvent.TYPE:
            self._store_feedback_txn(txn, event)
        elif event.type == RoomNameEvent.TYPE:
            self._store_room_name_txn(txn, event)
        elif event.type == RoomTopicEvent.TYPE:
            self._store_room_topic_txn(txn, event)
        elif event.type == RoomJoinRulesEvent.TYPE:
            self._store_join_rule(txn, event)
        elif event.type == RoomPowerLevelsEvent.TYPE:
            self._store_power_levels(txn, event)
        elif event.type == RoomAddStateLevelEvent.TYPE:
            self._store_add_state_level(txn, event)
        elif event.type == RoomSendEventLevelEvent.TYPE:
            self._store_send_event_level(txn, event)
        elif event.type == RoomOpsPowerLevelsEvent.TYPE:
            self._store_ops_level(txn, event)

        vals = {
            "topological_ordering": event.depth,
            "event_id": event.event_id,
            "type": event.type,
            "room_id": event.room_id,
            "content": json.dumps(event.content),
            "processed": True,
        }

        if stream_ordering is not None:
            vals["stream_ordering"] = stream_ordering

        if hasattr(event, "outlier"):
            vals["outlier"] = event.outlier
        else:
            vals["outlier"] = False

        unrec = {
            k: v
            for k, v in event.get_full_dict().items()
            if k not in vals.keys()
        }
        vals["unrecognized_keys"] = json.dumps(unrec)

        try:
            self._simple_insert_txn(txn, "events", vals)
        except:
            logger.exception(
                "Failed to persist, probably duplicate: %s",
                event.event_id
            )
            txn.rollback()
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

            self._simple_insert_txn(txn, "state_events", vals)

            self._simple_insert_txn(
                txn,
                "current_state_events",
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "type": event.type,
                    "state_key": event.state_key,
                }
            )

        return self._get_room_events_max_id_txn(txn)

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

        events = yield self._parse_events(results)
        defer.returnValue(events)

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

    def snapshot_room(self, room_id, user_id, state_type=None, state_key=None):
        """Snapshot the room for an update by a user
        Args:
            room_id (synapse.types.RoomId): The room to snapshot.
            user_id (synapse.types.UserId): The user to snapshot the room for.
            state_type (str): Optional state type to snapshot.
            state_key (str): Optional state key to snapshot.
        Returns:
            synapse.storage.Snapshot: A snapshot of the state of the room.
        """
        def _snapshot(txn):
            membership_state = self._get_room_member(txn, user_id, room_id)
            prev_pdus = self._get_latest_pdus_in_context(
                txn, room_id
            )
            if state_type is not None and state_key is not None:
                prev_state_pdu = self._get_current_state_pdu(
                    txn, room_id, state_type, state_key
                )
            else:
                prev_state_pdu = None

            return Snapshot(
                store=self,
                room_id=room_id,
                user_id=user_id,
                prev_pdus=prev_pdus,
                membership_state=membership_state,
                state_type=state_type,
                state_key=state_key,
                prev_state_pdu=prev_state_pdu,
            )

        return self._db_pool.runInteraction(_snapshot)


class Snapshot(object):
    """Snapshot of the state of a room
    Args:
        store (DataStore): The datastore.
        room_id (RoomId): The room of the snapshot.
        user_id (UserId): The user this snapshot is for.
        prev_pdus (list): The list of PDU ids this snapshot is after.
        membership_state (RoomMemberEvent): The current state of the user in
            the room.
        state_type (str, optional): State type captured by the snapshot
        state_key (str, optional): State key captured by the snapshot
        prev_state_pdu (PduEntry, optional): pdu id of
            the previous value of the state type and key in the room.
    """

    def __init__(self, store, room_id, user_id, prev_pdus,
                 membership_state, state_type=None, state_key=None,
                 prev_state_pdu=None):
        self.store = store
        self.room_id = room_id
        self.user_id = user_id
        self.prev_pdus = prev_pdus
        self.membership_state = membership_state
        self.state_type = state_type
        self.state_key = state_key
        self.prev_state_pdu = prev_state_pdu

    def fill_out_prev_events(self, event):
        if hasattr(event, "prev_events"):
            return

        es = [
            "%s@%s" % (p_id, origin) for p_id, origin, _ in self.prev_pdus
        ]

        event.prev_events = [e for e in es if e != event.event_id]

        if self.prev_pdus:
            event.depth = max([int(v) for _, _, v in self.prev_pdus]) + 1
        else:
            event.depth = 0


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
