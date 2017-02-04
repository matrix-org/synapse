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

from ._base import BaseSlavedStoreTestCase

from synapse.events import FrozenEvent, _EventInternalMetadata
from synapse.events.snapshot import EventContext
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.storage.roommember import RoomsForUser

from twisted.internet import defer


USER_ID = "@feeling:blue"
USER_ID_2 = "@bright:blue"
OUTLIER = {"outlier": True}
ROOM_ID = "!room:blue"


def dict_equals(self, other):
    return self.__dict__ == other.__dict__


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
        self.unpatches = [
            patch__eq__(_EventInternalMetadata),
            patch__eq__(FrozenEvent),
        ]
        return super(SlavedEventStoreTestCase, self).setUp()

    def tearDown(self):
        [unpatch() for unpatch in self.unpatches]

    @defer.inlineCallbacks
    def test_get_latest_event_ids_in_room(self):
        create = yield self.persist(type="m.room.create", key="", creator=USER_ID)
        yield self.replicate()
        yield self.check(
            "get_latest_event_ids_in_room", (ROOM_ID,), [create.event_id]
        )

        join = yield self.persist(
            type="m.room.member", key=USER_ID, membership="join",
            prev_events=[(create.event_id, {})],
        )
        yield self.replicate()
        yield self.check(
            "get_latest_event_ids_in_room", (ROOM_ID,), [join.event_id]
        )

    @defer.inlineCallbacks
    def test_redactions(self):
        yield self.persist(type="m.room.create", key="", creator=USER_ID)
        yield self.persist(type="m.room.member", key=USER_ID, membership="join")

        msg = yield self.persist(
            type="m.room.message", msgtype="m.text", body="Hello"
        )
        yield self.replicate()
        yield self.check("get_event", [msg.event_id], msg)

        redaction = yield self.persist(
            type="m.room.redaction", redacts=msg.event_id
        )
        yield self.replicate()

        msg_dict = msg.get_dict()
        msg_dict["content"] = {}
        msg_dict["unsigned"]["redacted_by"] = redaction.event_id
        msg_dict["unsigned"]["redacted_because"] = redaction
        redacted = FrozenEvent(msg_dict, msg.internal_metadata.get_dict())
        yield self.check("get_event", [msg.event_id], redacted)

    @defer.inlineCallbacks
    def test_backfilled_redactions(self):
        yield self.persist(type="m.room.create", key="", creator=USER_ID)
        yield self.persist(type="m.room.member", key=USER_ID, membership="join")

        msg = yield self.persist(
            type="m.room.message", msgtype="m.text", body="Hello"
        )
        yield self.replicate()
        yield self.check("get_event", [msg.event_id], msg)

        redaction = yield self.persist(
            type="m.room.redaction", redacts=msg.event_id, backfill=True
        )
        yield self.replicate()

        msg_dict = msg.get_dict()
        msg_dict["content"] = {}
        msg_dict["unsigned"]["redacted_by"] = redaction.event_id
        msg_dict["unsigned"]["redacted_because"] = redaction
        redacted = FrozenEvent(msg_dict, msg.internal_metadata.get_dict())
        yield self.check("get_event", [msg.event_id], redacted)

    @defer.inlineCallbacks
    def test_invites(self):
        yield self.check("get_invited_rooms_for_user", [USER_ID_2], [])
        event = yield self.persist(
            type="m.room.member", key=USER_ID_2, membership="invite"
        )
        yield self.replicate()
        yield self.check("get_invited_rooms_for_user", [USER_ID_2], [RoomsForUser(
            ROOM_ID, USER_ID, "invite", event.event_id,
            event.internal_metadata.stream_ordering
        )])

    @defer.inlineCallbacks
    def test_push_actions_for_user(self):
        yield self.persist(type="m.room.create", creator=USER_ID)
        yield self.persist(type="m.room.join", key=USER_ID, membership="join")
        yield self.persist(
            type="m.room.join", sender=USER_ID, key=USER_ID_2, membership="join"
        )
        event1 = yield self.persist(
            type="m.room.message", msgtype="m.text", body="hello"
        )
        yield self.replicate()
        yield self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2, event1.event_id],
            {"highlight_count": 0, "notify_count": 0}
        )

        yield self.persist(
            type="m.room.message", msgtype="m.text", body="world",
            push_actions=[(USER_ID_2, ["notify"])],
        )
        yield self.replicate()
        yield self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2, event1.event_id],
            {"highlight_count": 0, "notify_count": 1}
        )

        yield self.persist(
            type="m.room.message", msgtype="m.text", body="world",
            push_actions=[(USER_ID_2, [
                "notify", {"set_tweak": "highlight", "value": True}
            ])],
        )
        yield self.replicate()
        yield self.check(
            "get_unread_event_push_actions_by_room_for_user",
            [ROOM_ID, USER_ID_2, event1.event_id],
            {"highlight_count": 1, "notify_count": 2}
        )

    event_id = 0

    @defer.inlineCallbacks
    def persist(
        self, sender=USER_ID, room_id=ROOM_ID, type={}, key=None, internal={},
        state=None, reset_state=False, backfill=False,
        depth=None, prev_events=[], auth_events=[], prev_state=[], redacts=None,
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
            latest_event_ids = yield self.master_store.get_latest_event_ids_in_room(
                room_id
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
            state_ids = {
                key: e.event_id for key, e in state.items()
            }
            context = EventContext()
            context.current_state_ids = state_ids
            context.prev_state_ids = state_ids
        elif not backfill:
            state_handler = self.hs.get_state_handler()
            context = yield state_handler.compute_event_context(event)
        else:
            context = EventContext()

        context.push_actions = push_actions

        ordering = None
        if backfill:
            yield self.master_store.persist_events(
                [(event, context)], backfilled=True
            )
        else:
            ordering, _ = yield self.master_store.persist_event(
                event, context,
            )

        if ordering:
            event.internal_metadata.stream_ordering = ordering

        defer.returnValue(event)
