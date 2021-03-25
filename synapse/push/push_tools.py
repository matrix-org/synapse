# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
from typing import Dict

from synapse.events import EventBase
from synapse.push.presentable_names import calculate_room_name, name_from_member_event
from synapse.storage import Storage
from synapse.storage.databases.main import DataStore


async def get_badge_count(store: DataStore, user_id: str, group_by_room: bool) -> int:
    invites = await store.get_invited_rooms_for_local_user(user_id)
    joins = await store.get_rooms_for_user(user_id)

    my_receipts_by_room = await store.get_receipts_for_user(user_id, "m.read")

    badge = len(invites)

    for room_id in joins:
        if room_id in my_receipts_by_room:
            last_unread_event_id = my_receipts_by_room[room_id]

            notifs = await (
                store.get_unread_event_push_actions_by_room_for_user(
                    room_id, user_id, last_unread_event_id
                )
            )
            if notifs["notify_count"] == 0:
                continue

            if group_by_room:
                # return one badge count per conversation
                badge += 1
            else:
                # increment the badge count by the number of unread messages in the room
                badge += notifs["notify_count"]
    return badge


async def get_context_for_event(
    storage: Storage, ev: EventBase, user_id: str
) -> Dict[str, str]:
    ctx = {}

    room_state_ids = await storage.state.get_state_ids_for_event(ev.event_id)

    # we no longer bother setting room_alias, and make room_name the
    # human-readable name instead, be that m.room.name, an alias or
    # a list of people in the room
    name = await calculate_room_name(
        storage.main, room_state_ids, user_id, fallback_to_single_member=False
    )
    if name:
        ctx["name"] = name

    sender_state_event_id = room_state_ids[("m.room.member", ev.sender)]
    sender_state_event = await storage.main.get_event(sender_state_event_id)
    ctx["sender_display_name"] = name_from_member_event(sender_state_event)

    return ctx
