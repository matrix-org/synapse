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

from synapse.types import UserID
from synapse.events import FrozenEvent
from synapse.events.snapshot import EventContext

from twisted.internet import defer

USER_ID = "@feeling:blue"
USER = UserID.from_string(USER_ID)
OUTLIER = {"outlier": True}
ROOM_ID = "!room:blue"


class SlavedEventStoreTestCase(BaseSlavedStoreTestCase):

    @defer.inlineCallbacks
    def test_room_name_and_aliases(self):
        create = yield self.persist(type="m.room.create", key="", creator=USER_ID)
        yield self.persist(type="m.room.member", key=USER_ID, membership="join")
        yield self.persist(type="m.room.name", key="", name="name1")
        yield self.persist(
            type="m.room.aliases", key="blue", aliases=["#1:blue"]
        )
        yield self.replicate()
        yield self.check(
            "get_room_name_and_aliases", (ROOM_ID,), ("name1", ["#1:blue"])
        )

        # Set the room name.
        yield self.persist(type="m.room.name", key="", name="name2")
        yield self.replicate()
        yield self.check(
            "get_room_name_and_aliases", (ROOM_ID,), ("name2", ["#1:blue"])
        )

        # Set the room aliases.
        yield self.persist(
            type="m.room.aliases", key="blue", aliases=["#2:blue"]
        )
        yield self.replicate()
        yield self.check(
            "get_room_name_and_aliases", (ROOM_ID,), ("name2", ["#2:blue"])
        )

        # Leave and join the room clobbering the state.
        yield self.persist(type="m.room.member", key=USER_ID, membership="leave")
        yield self.persist(
            type="m.room.member", key=USER_ID, membership="join",
            reset_state=[create]
        )
        yield self.replicate()

        yield self.check(
            "get_room_name_and_aliases", (ROOM_ID,), (None, [])
        )

    event_id = 0

    @defer.inlineCallbacks
    def persist(
            self, sender=USER_ID, room_id=ROOM_ID, type={}, key=None,
            internal={},
            state=None, reset_state=False, backfill=False,
            depth=None, prev_events=[], auth_events=[], prev_state=[],
            **content
    ):
        if depth is None:
            depth = self.event_id

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

        event = FrozenEvent(event_dict, internal_metadata_dict=internal)

        self.event_id += 1

        context = EventContext(current_state=state)

        if backfill:
            yield self.master_store.persist_events(
                [(event, context)], backfilled=True
            )
        else:
            yield self.master_store.persist_event(
                event, context, current_state=reset_state
            )
        defer.returnValue(event)
