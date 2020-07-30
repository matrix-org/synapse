# -*- coding: utf-8 -*-
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
import re

from synapse.api.constants import EventTypes

logger = logging.getLogger(__name__)

# intentionally looser than what aliases we allow to be registered since
# other HSes may allow aliases that we would not
ALIAS_RE = re.compile(r"^#.*:.+$")

ALL_ALONE = "Empty Room"


async def calculate_room_name(
    store,
    room_state_ids,
    user_id,
    fallback_to_members=True,
    fallback_to_single_member=True,
):
    """
    Works out a user-facing name for the given room as per Matrix
    spec recommendations.
    Does not yet support internationalisation.
    Args:
        room_state: Dictionary of the room's state
        user_id: The ID of the user to whom the room name is being presented
        fallback_to_members: If False, return None instead of generating a name
                             based on the room's members if the room has no
                             title or aliases.

    Returns:
        (string or None) A human readable name for the room.
    """
    # does it have a name?
    if (EventTypes.Name, "") in room_state_ids:
        m_room_name = await store.get_event(
            room_state_ids[(EventTypes.Name, "")], allow_none=True
        )
        if m_room_name and m_room_name.content and m_room_name.content["name"]:
            return m_room_name.content["name"]

    # does it have a canonical alias?
    if (EventTypes.CanonicalAlias, "") in room_state_ids:
        canon_alias = await store.get_event(
            room_state_ids[(EventTypes.CanonicalAlias, "")], allow_none=True
        )
        if (
            canon_alias
            and canon_alias.content
            and canon_alias.content["alias"]
            and _looks_like_an_alias(canon_alias.content["alias"])
        ):
            return canon_alias.content["alias"]

    # at this point we're going to need to search the state by all state keys
    # for an event type, so rearrange the data structure
    room_state_bytype_ids = _state_as_two_level_dict(room_state_ids)

    if not fallback_to_members:
        return None

    my_member_event = None
    if (EventTypes.Member, user_id) in room_state_ids:
        my_member_event = await store.get_event(
            room_state_ids[(EventTypes.Member, user_id)], allow_none=True
        )

    if (
        my_member_event is not None
        and my_member_event.content["membership"] == "invite"
    ):
        if (EventTypes.Member, my_member_event.sender) in room_state_ids:
            inviter_member_event = await store.get_event(
                room_state_ids[(EventTypes.Member, my_member_event.sender)],
                allow_none=True,
            )
            if inviter_member_event:
                if fallback_to_single_member:
                    return "Invite from %s" % (
                        name_from_member_event(inviter_member_event),
                    )
                else:
                    return
        else:
            return "Room Invite"

    # we're going to have to generate a name based on who's in the room,
    # so find out who is in the room that isn't the user.
    if EventTypes.Member in room_state_bytype_ids:
        member_events = await store.get_events(
            list(room_state_bytype_ids[EventTypes.Member].values())
        )
        all_members = [
            ev
            for ev in member_events.values()
            if ev.content["membership"] == "join"
            or ev.content["membership"] == "invite"
        ]
        # Sort the member events oldest-first so the we name people in the
        # order the joined (it should at least be deterministic rather than
        # dictionary iteration order)
        all_members.sort(key=lambda e: e.origin_server_ts)
        other_members = [m for m in all_members if m.state_key != user_id]
    else:
        other_members = []
        all_members = []

    if len(other_members) == 0:
        if len(all_members) == 1:
            # self-chat, peeked room with 1 participant,
            # or inbound invite, or outbound 3PID invite.
            if all_members[0].sender == user_id:
                if EventTypes.ThirdPartyInvite in room_state_bytype_ids:
                    third_party_invites = room_state_bytype_ids[
                        EventTypes.ThirdPartyInvite
                    ].values()

                    if len(third_party_invites) > 0:
                        # technically third party invite events are not member
                        # events, but they are close enough

                        # FIXME: no they're not - they look nothing like a member;
                        # they have a great big encrypted thing as their name to
                        # prevent leaking the 3PID name...
                        # return "Inviting %s" % (
                        #     descriptor_from_member_events(third_party_invites)
                        # )
                        return "Inviting email address"
                    else:
                        return ALL_ALONE
            else:
                return name_from_member_event(all_members[0])
        else:
            return ALL_ALONE
    elif len(other_members) == 1 and not fallback_to_single_member:
        return
    else:
        return descriptor_from_member_events(other_members)


def descriptor_from_member_events(member_events):
    """Get a description of the room based on the member events.

    Args:
        member_events (Iterable[FrozenEvent])

    Returns:
        str
    """

    member_events = list(member_events)

    if len(member_events) == 0:
        return "nobody"
    elif len(member_events) == 1:
        return name_from_member_event(member_events[0])
    elif len(member_events) == 2:
        return "%s and %s" % (
            name_from_member_event(member_events[0]),
            name_from_member_event(member_events[1]),
        )
    else:
        return "%s and %d others" % (
            name_from_member_event(member_events[0]),
            len(member_events) - 1,
        )


def name_from_member_event(member_event):
    if (
        member_event.content
        and "displayname" in member_event.content
        and member_event.content["displayname"]
    ):
        return member_event.content["displayname"]
    return member_event.state_key


def _state_as_two_level_dict(state):
    ret = {}
    for k, v in state.items():
        ret.setdefault(k[0], {})[k[1]] = v
    return ret


def _looks_like_an_alias(string):
    return ALIAS_RE.match(string) is not None
