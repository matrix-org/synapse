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

from twisted.internet import defer

from synapse.push.presentable_names import calculate_room_name, name_from_member_event


@defer.inlineCallbacks
def get_badge_count(store, user_id):
    invites = yield store.get_invited_rooms_for_user(user_id)
    joins = yield store.get_rooms_for_user(user_id)

    my_receipts_by_room = yield store.get_receipts_for_user(
        user_id, "m.read",
    )

    badge = len(invites)

    for room_id in joins:
        if room_id in my_receipts_by_room:
            last_unread_event_id = my_receipts_by_room[room_id]

            notifs = yield (
                store.get_unread_event_push_actions_by_room_for_user(
                    room_id, user_id, last_unread_event_id
                )
            )
            # return one badge count per conversation, as count per
            # message is so noisy as to be almost useless
            badge += 1 if notifs["notify_count"] else 0
    defer.returnValue(badge)


@defer.inlineCallbacks
def get_context_for_event(store, state_handler, ev, user_id):
    ctx = {}

    room_state_ids = yield store.get_state_ids_for_event(ev.event_id)

    # we no longer bother setting room_alias, and make room_name the
    # human-readable name instead, be that m.room.name, an alias or
    # a list of people in the room
    name = yield calculate_room_name(
        store, room_state_ids, user_id, fallback_to_single_member=False
    )
    if name:
        ctx['name'] = name

    sender_state_event_id = room_state_ids[("m.room.member", ev.sender)]
    sender_state_event = yield store.get_event(sender_state_event_id)
    ctx['sender_display_name'] = name_from_member_event(sender_state_event)

    defer.returnValue(ctx)
