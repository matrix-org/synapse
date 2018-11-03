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

from canonicaljson import encode_canonical_json

from synapse.events import FrozenEvent, _EventInternalMetadata
from synapse.events.snapshot import EventContext
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.storage.roommember import RoomsForUser

from ._base import BaseSlavedStoreTestCase

USER_ID = "@feeling:blue"
USER_ID_2 = "@bright:blue"
OUTLIER = {"outlier": True}
ROOM_ID = "!room:blue"


def dict_equals(self, other):
    me = encode_canonical_json(self._event_dict)
    them = encode_canonical_json(other._event_dict)
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
        # whether lists of events match using assertEquals
        self.unpatches = [patch__eq__(_EventInternalMetadata), patch__eq__(FrozenEvent)]
        return super(SlavedEventStoreTestCase, self).setUp()

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
        redacted = FrozenEvent(msg_dict, msg.internal_metadata.get_dict())
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
        redacted = FrozenEvent(msg_dict, msg.internal_metadata.get_dict())
        self.check("get_event", [msg.event_id], redacted)

    def test_invites(self):
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.check("get_invited_rooms_for_user", [USER_ID_2], [])
        event = self.persist(type="m.room.member", key=USER_ID_2, membership="invite")

        self.replicate()

        self.check(
            "get_invited_rooms_for_user",
            [USER_ID_2],
            [
                RoomsForUser(
                    ROOM_ID,
                    USER_ID,
                    "invite",
                    event.event_id,
                    event.internal_metadata.stream_ordering,
                )
            ],
        )

    def test_push_actions_for_user(self):
        self.persist(type="m.room.create", key="", creator=USER_ID)
        self.persist(type="m.room.join", key=USER_ID, membership="join")
        self.persist(
            type="m.room.join", sender=USER_ID, key=USER_ID_2, membership="join"
        )
        event1 = self.persist(type="m.room.message", msgtype="m.text", body="hello")
        self.replicate()
        self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2, event1.event_id],
            {"highlight_count": 0, "notify_count": 0},
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
            [ROOM_ID, USER_ID_2, event1.event_id],
            {"highlight_count": 0, "notify_count": 1},
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
            [ROOM_ID, USER_ID_2, event1.event_id],
            {"highlight_count": 1, "notify_count": 2},
        )

    event_id = 0

    def persist(
        self,
        sender=USER_ID,
        room_id=ROOM_ID,
        type={},
        key=None,
        internal={},
        state=None,
        reset_state=False,
        backfill=False,
        depth=None,
        prev_events=[],
        auth_events=[],
        prev_state=[],
        redacts=None,
        push_actions=[],
        **content
    ):
        """
        Returns:
            synapse.events.FrozenEvent: The event that was persisted.
        """
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

        event = FrozenEvent(event_dict, internal_metadata_dict=internal)

        self.event_id += 1

        if state is not None:
            state_ids = {key: e.event_id for key, e in state.items()}
            context = EventContext.with_state(
                state_group=None, current_state_ids=state_ids, prev_state_ids=state_ids
            )
        else:
            state_handler = self.hs.get_state_handler()
            context = self.get_success(state_handler.compute_event_context(event))

        self.master_store.add_push_actions_to_staging(
            event.event_id, {user_id: actions for user_id, actions in push_actions}
        )

        ordering = None
        if backfill:
            self.get_success(
                self.master_store.persist_events([(event, context)], backfilled=True)
            )
        else:
            ordering, _ = self.get_success(
                self.master_store.persist_event(event, context)
            )

        if ordering:
            event.internal_metadata.stream_ordering = ordering

        return event
