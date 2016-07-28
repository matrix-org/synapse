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

import re
import logging

logger = logging.getLogger(__name__)

# intentionally looser than what aliases we allow to be registered since
# other HSes may allow aliases that we would not
ALIAS_RE = re.compile(r"^#.*:.+$")

ALL_ALONE = "Empty Room"


def calculate_room_name(room_state, user_id, fallback_to_members=True,
                        fallback_to_single_member=True):
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
    if ("m.room.name", "") in room_state:
        m_room_name = room_state[("m.room.name", "")]
        if m_room_name.content and m_room_name.content["name"]:
            return m_room_name.content["name"]

    # does it have a canonical alias?
    if ("m.room.canonical_alias", "") in room_state:
        canon_alias = room_state[("m.room.canonical_alias", "")]
        if (
            canon_alias.content and canon_alias.content["alias"] and
            _looks_like_an_alias(canon_alias.content["alias"])
        ):
            return canon_alias.content["alias"]

    # at this point we're going to need to search the state by all state keys
    # for an event type, so rearrange the data structure
    room_state_bytype = _state_as_two_level_dict(room_state)

    # right then, any aliases at all?
    if "m.room.aliases" in room_state_bytype:
        m_room_aliases = room_state_bytype["m.room.aliases"]
        if len(m_room_aliases.values()) > 0:
            first_alias_event = m_room_aliases.values()[0]
            if first_alias_event.content and first_alias_event.content["aliases"]:
                the_aliases = first_alias_event.content["aliases"]
                if len(the_aliases) > 0 and _looks_like_an_alias(the_aliases[0]):
                    return the_aliases[0]

    if not fallback_to_members:
        return None

    my_member_event = None
    if ("m.room.member", user_id) in room_state:
        my_member_event = room_state[("m.room.member", user_id)]

    if (
        my_member_event is not None and
        my_member_event.content['membership'] == "invite"
    ):
        if ("m.room.member", my_member_event.sender) in room_state:
            inviter_member_event = room_state[("m.room.member", my_member_event.sender)]
            if fallback_to_single_member:
                return "Invite from %s" % (name_from_member_event(inviter_member_event),)
            else:
                return None
        else:
            return "Room Invite"

    # we're going to have to generate a name based on who's in the room,
    # so find out who is in the room that isn't the user.
    if "m.room.member" in room_state_bytype:
        all_members = [
            ev for ev in room_state_bytype["m.room.member"].values()
            if ev.content['membership'] == "join" or ev.content['membership'] == "invite"
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
                if "m.room.third_party_invite" in room_state_bytype:
                    third_party_invites = (
                        room_state_bytype["m.room.third_party_invite"].values()
                    )

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
        return None
    else:
        return descriptor_from_member_events(other_members)


def descriptor_from_member_events(member_events):
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
        member_event.content and "displayname" in member_event.content and
        member_event.content["displayname"]
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
