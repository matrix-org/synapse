# Copyright 2016 OpenMarket Ltd
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
from typing import Iterable, Optional

from canonicaljson import encode_canonical_json
from parameterized import parameterized

from synapse.api.constants import ReceiptTypes
from synapse.api.room_versions import RoomVersions
from synapse.events import FrozenEvent, _EventInternalMetadata, make_event_from_dict
from synapse.handlers.room import RoomEventSource
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.storage.databases.main.event_push_actions import (
    NotifCounts,
    RoomNotifCounts,
)
from synapse.storage.roommember import GetRoomsForUserWithStreamOrdering, RoomsForUser
from synapse.types import PersistedEventPosition

from tests.server import FakeTransport

from ._base import BaseSlavedStoreTestCase

USER_ID = "@feeling:test"
USER_ID_2 = "@bright:test"
OUTLIER = {"outlier": True}
ROOM_ID = "!room:test"

logger = logging.getLogger(__name__)


def dict_equals(self, other):
    me = encode_canonical_json(self.get_pdu_json())
    them = encode_canonical_json(other.get_pdu_json())
    return me == them


def patch__eq__(cls):
    eq = getattr(cls, "__eq__", None)
    cls.__eq__ = dict_equals

    def unpatch():
        if eq is not None:
            cls.__eq__ = eq

    return unpatch


class SlavedEventStoreTestCase(BaseSlavedStoreTestCase):

    STORE_TYPE = SlavedEventStore

    def setUp(self):
        # Patch up the equality operator for events so that we can check
        # whether lists of events match using assertEqual
        self.unpatches = [patch__eq__(_EventInternalMetadata), patch__eq__(FrozenEvent)]
        return super().setUp()

    def prepare(self, *args, **kwargs):
        super().prepare(*args, **kwargs)

        self.get_success(
            self.master_store.store_room(
                ROOM_ID,
                USER_ID,
                is_public=False,
                room_version=RoomVersions.V1,
            )
        )

    def tearDown(self):
        [unpatch() for unpatch in self.unpatches]

    def test_get_latest_event_ids_in_room(self):
        create = self.persist(type="m.room.create", key="", creator=USER_ID)
        self.replicate()
        self.check("get_latest_event_ids_in_room", (ROOM_ID,), [create.event_id])

        join = self.persist(
            type="m.room.member",
            key=USER_ID,
            membership="join",
            prev_events=[(create.event_id, {})],
        )
        self.replicate()
        self.check("get_latest_event_ids_in_room", (ROOM_ID,), [join.event_id])

    def test_redactions(self):
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.persist(type="m.room.member", key=USER_ID, membership="join")

        msg = self.persist(type="m.room.message", msgtype="m.text", body="Hello")
        self.replicate()
        self.check("get_event", [msg.event_id], msg)

        redaction = self.persist(type="m.room.redaction", redacts=msg.event_id)
        self.replicate()

        msg_dict = msg.get_dict()
        msg_dict["content"] = {}
        msg_dict["unsigned"]["redacted_by"] = redaction.event_id
        msg_dict["unsigned"]["redacted_because"] = redaction
        redacted = make_event_from_dict(
            msg_dict, internal_metadata_dict=msg.internal_metadata.get_dict()
        )
        self.check("get_event", [msg.event_id], redacted)

    def test_backfilled_redactions(self):
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.persist(type="m.room.member", key=USER_ID, membership="join")

        msg = self.persist(type="m.room.message", msgtype="m.text", body="Hello")
        self.replicate()
        self.check("get_event", [msg.event_id], msg)

        redaction = self.persist(
            type="m.room.redaction", redacts=msg.event_id, backfill=True
        )
        self.replicate()

        msg_dict = msg.get_dict()
        msg_dict["content"] = {}
        msg_dict["unsigned"]["redacted_by"] = redaction.event_id
        msg_dict["unsigned"]["redacted_because"] = redaction
        redacted = make_event_from_dict(
            msg_dict, internal_metadata_dict=msg.internal_metadata.get_dict()
        )
        self.check("get_event", [msg.event_id], redacted)

    def test_invites(self):
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.check("get_invited_rooms_for_local_user", [USER_ID_2], [])
        event = self.persist(type="m.room.member", key=USER_ID_2, membership="invite")

        self.replicate()

        self.check(
            "get_invited_rooms_for_local_user",
            [USER_ID_2],
            [
                RoomsForUser(
                    ROOM_ID,
                    USER_ID,
                    "invite",
                    event.event_id,
                    event.internal_metadata.stream_ordering,
                    RoomVersions.V1.identifier,
                )
            ],
        )

    @parameterized.expand([(True,), (False,)])
    def test_push_actions_for_user(self, send_receipt: bool):
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.persist(type="m.room.member", key=USER_ID, membership="join")
        self.persist(
            type="m.room.member", sender=USER_ID, key=USER_ID_2, membership="join"
        )
        event1 = self.persist(type="m.room.message", msgtype="m.text", body="hello")
        self.replicate()

        if send_receipt:
            self.get_success(
                self.master_store.insert_receipt(
                    ROOM_ID, ReceiptTypes.READ, USER_ID_2, [event1.event_id], None, {}
                )
            )

        self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2],
            RoomNotifCounts(
                NotifCounts(highlight_count=0, unread_count=0, notify_count=0), {}
            ),
        )

        self.persist(
            type="m.room.message",
            msgtype="m.text",
            body="world",
            push_actions=[(USER_ID_2, ["notify"])],
        )
        self.replicate()
        self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2],
            RoomNotifCounts(
                NotifCounts(highlight_count=0, unread_count=0, notify_count=1), {}
            ),
        )

        self.persist(
            type="m.room.message",
            msgtype="m.text",
            body="world",
            push_actions=[
                (USER_ID_2, ["notify", {"set_tweak": "highlight", "value": True}])
            ],
        )
        self.replicate()
        self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2],
            RoomNotifCounts(
                NotifCounts(highlight_count=1, unread_count=0, notify_count=2), {}
            ),
        )

    def test_get_rooms_for_user_with_stream_ordering(self):
        """Check that the cache on get_rooms_for_user_with_stream_ordering is invalidated
        by rows in the events stream
        """
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.persist(type="m.room.member", key=USER_ID, membership="join")
        self.replicate()
        self.check("get_rooms_for_user_with_stream_ordering", (USER_ID_2,), set())

        j2 = self.persist(
            type="m.room.member", sender=USER_ID_2, key=USER_ID_2, membership="join"
        )
        self.replicate()

        expected_pos = PersistedEventPosition(
            "master", j2.internal_metadata.stream_ordering
        )
        self.check(
            "get_rooms_for_user_with_stream_ordering",
            (USER_ID_2,),
            {GetRoomsForUserWithStreamOrdering(ROOM_ID, expected_pos)},
        )

    def test_get_rooms_for_user_with_stream_ordering_with_multi_event_persist(self):
        """Check that current_state invalidation happens correctly with multiple events
        in the persistence batch.

        This test attempts to reproduce a race condition between the event persistence
        loop and a worker-based Sync handler.

        The problem occurred when the master persisted several events in one batch. It
        only updates the current_state at the end of each batch, so the obvious thing
        to do is then to issue a current_state_delta stream update corresponding to the
        last stream_id in the batch.

        However, that raises the possibility that a worker will see the replication
        notification for a join event before the current_state caches are invalidated.

        The test involves:
         * creating a join and a message event for a user, and persisting them in the
           same batch

         * controlling the replication stream so that updates are sent gradually

         * between each bunch of replication updates, check that we see a consistent
           snapshot of the state.
        """
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.persist(type="m.room.member", key=USER_ID, membership="join")
        self.replicate()
        self.check("get_rooms_for_user_with_stream_ordering", (USER_ID_2,), set())

        # limit the replication rate
        repl_transport = self._server_transport
        assert isinstance(repl_transport, FakeTransport)
        repl_transport.autoflush = False

        # build the join and message events and persist them in the same batch.
        logger.info("----- build test events ------")
        j2, j2ctx = self.build_event(
            type="m.room.member", sender=USER_ID_2, key=USER_ID_2, membership="join"
        )
        msg, msgctx = self.build_event()
        self.get_success(
            self._storage_controllers.persistence.persist_events(
                [(j2, j2ctx), (msg, msgctx)]
            )
        )
        self.replicate()

        event_source = RoomEventSource(self.hs)
        event_source.store = self.slaved_store
        current_token = event_source.get_current_key()

        # gradually stream out the replication
        while repl_transport.buffer:
            logger.info("------ flush ------")
            repl_transport.flush(30)
            self.pump(0)

            prev_token = current_token
            current_token = event_source.get_current_key()

            # attempt to replicate the behaviour of the sync handler.
            #
            # First, we get a list of the rooms we are joined to
            joined_rooms = self.get_success(
                self.slaved_store.get_rooms_for_user_with_stream_ordering(USER_ID_2)
            )

            # Then, we get a list of the events since the last sync
            membership_changes = self.get_success(
                self.slaved_store.get_membership_changes_for_user(
                    USER_ID_2, prev_token, current_token
                )
            )

            logger.info(
                "%s->%s: joined_rooms=%r membership_changes=%r",
                prev_token,
                current_token,
                joined_rooms,
                membership_changes,
            )

            # the membership change is only any use to us if the room is in the
            # joined_rooms list.
            if membership_changes:
                expected_pos = PersistedEventPosition(
                    "master", j2.internal_metadata.stream_ordering
                )
                self.assertEqual(
                    joined_rooms,
                    {GetRoomsForUserWithStreamOrdering(ROOM_ID, expected_pos)},
                )

    event_id = 0

    def persist(self, backfill=False, **kwargs):
        """
        Returns:
            synapse.events.FrozenEvent: The event that was persisted.
        """
        event, context = self.build_event(**kwargs)

        if backfill:
            self.get_success(
                self._storage_controllers.persistence.persist_events(
                    [(event, context)], backfilled=True
                )
            )
        else:
            self.get_success(
                self._storage_controllers.persistence.persist_event(event, context)
            )

        return event

    def build_event(
        self,
        sender=USER_ID,
        room_id=ROOM_ID,
        type="m.room.message",
        key=None,
        internal: Optional[dict] = None,
        depth=None,
        prev_events: Optional[list] = None,
        auth_events: Optional[list] = None,
        prev_state: Optional[list] = None,
        redacts=None,
        push_actions: Iterable = frozenset(),
        **content,
    ):
        prev_events = prev_events or []
        auth_events = auth_events or []
        prev_state = prev_state or []

        if depth is None:
            depth = self.event_id

        if not prev_events:
            latest_event_ids = self.get_success(
                self.master_store.get_latest_event_ids_in_room(room_id)
            )
            prev_events = [(ev_id, {}) for ev_id in latest_event_ids]

        event_dict = {
            "sender": sender,
            "type": type,
            "content": content,
            "event_id": "$%d:blue" % (self.event_id,),
            "room_id": room_id,
            "depth": depth,
            "origin_server_ts": self.event_id,
            "prev_events": prev_events,
            "auth_events": auth_events,
        }
        if key is not None:
            event_dict["state_key"] = key
            event_dict["prev_state"] = prev_state

        if redacts is not None:
            event_dict["redacts"] = redacts

        event = make_event_from_dict(event_dict, internal_metadata_dict=internal or {})

        self.event_id += 1
        state_handler = self.hs.get_state_handler()
        context = self.get_success(state_handler.compute_event_context(event))

        self.get_success(
            self.master_store.add_push_actions_to_staging(
                event.event_id,
                {user_id: actions for user_id, actions in push_actions},
                False,
                "main",
            )
        )
        return event, context
