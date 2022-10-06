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
from synapse.storage.controllers import StorageControllers
from synapse.storage.databases.main import DataStore
from synapse.util.async_helpers import concurrently_execute


async def get_badge_count(store: DataStore, user_id: str, group_by_room: bool) -> int:
    invites = await store.get_invited_rooms_for_local_user(user_id)
    joins = await store.get_rooms_for_user(user_id)

    badge = len(invites)

    room_notifs = []

    async def get_room_unread_count(room_id: str) -> None:
        room_notifs.append(
            await store.get_unread_event_push_actions_by_room_for_user(
                room_id,
                user_id,
            )
        )

    await concurrently_execute(get_room_unread_count, joins, 10)

    for notifs in room_notifs:
        # Combine the counts from all the threads.
        notify_count = notifs.main_timeline.notify_count + sum(
            n.notify_count for n in notifs.threads.values()
        )

        if notify_count == 0:
            continue

        if group_by_room:
            # return one badge count per conversation
            badge += 1
        else:
            # increment the badge count by the number of unread messages in the room
            badge += notify_count
    return badge


async def get_context_for_event(
    storage: StorageControllers, ev: EventBase, user_id: str
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
