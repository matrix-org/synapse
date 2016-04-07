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


@defer.inlineCallbacks
def get_badge_count(store, user_id):
    invites, joins = yield defer.gatherResults([
        store.get_invited_rooms_for_user(user_id),
        store.get_rooms_for_user(user_id),
    ], consumeErrors=True)

    my_receipts_by_room = yield store.get_receipts_for_user(
        user_id, "m.read",
    )

    badge = len(invites)

    for r in joins:
        if r.room_id in my_receipts_by_room:
            last_unread_event_id = my_receipts_by_room[r.room_id]

            notifs = yield (
                store.get_unread_event_push_actions_by_room_for_user(
                    r.room_id, user_id, last_unread_event_id
                )
            )
            badge += notifs["notify_count"]
    defer.returnValue(badge)


@defer.inlineCallbacks
def get_context_for_event(store, ev):
    name_aliases = yield store.get_room_name_and_aliases(
        ev.room_id
    )

    ctx = {'aliases': name_aliases[1]}
    if name_aliases[0] is not None:
        ctx['name'] = name_aliases[0]

    their_member_events_for_room = yield store.get_current_state(
        room_id=ev.room_id,
        event_type='m.room.member',
        state_key=ev.user_id
    )
    for mev in their_member_events_for_room:
        if mev.content['membership'] == 'join' and 'displayname' in mev.content:
            dn = mev.content['displayname']
            if dn is not None:
                ctx['sender_display_name'] = dn

    defer.returnValue(ctx)
