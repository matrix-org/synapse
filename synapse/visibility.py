# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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

from synapse.api.constants import Membership, EventTypes

from synapse.util.logcontext import preserve_fn, preserve_context_over_deferred

import logging


logger = logging.getLogger(__name__)


VISIBILITY_PRIORITY = (
    "world_readable",
    "shared",
    "invited",
    "joined",
)


MEMBERSHIP_PRIORITY = (
    Membership.JOIN,
    Membership.INVITE,
    Membership.KNOCK,
    Membership.LEAVE,
    Membership.BAN,
)


@defer.inlineCallbacks
def filter_events_for_clients(store, user_tuples, events, event_id_to_state):
    """ Returns dict of user_id -> list of events that user is allowed to
    see.

    Args:
        user_tuples (str, bool): (user id, is_peeking) for each user to be
            checked. is_peeking should be true if:
            * the user is not currently a member of the room, and:
            * the user has not been a member of the room since the
            given events
        events ([synapse.events.EventBase]): list of events to filter
    """
    forgotten = yield preserve_context_over_deferred(defer.gatherResults([
        defer.maybeDeferred(
            preserve_fn(store.who_forgot_in_room),
            room_id,
        )
        for room_id in frozenset(e.room_id for e in events)
    ], consumeErrors=True))

    # Set of membership event_ids that have been forgotten
    event_id_forgotten = frozenset(
        row["event_id"] for rows in forgotten for row in rows
    )

    ignore_dict_content = yield store.get_global_account_data_by_type_for_users(
        "m.ignored_user_list", user_ids=[user_id for user_id, _ in user_tuples]
    )

    # FIXME: This will explode if people upload something incorrect.
    ignore_dict = {
        user_id: frozenset(
            content.get("ignored_users", {}).keys() if content else []
        )
        for user_id, content in ignore_dict_content.items()
    }

    def allowed(event, user_id, is_peeking, ignore_list):
        """
        Args:
            event (synapse.events.EventBase): event to check
            user_id (str)
            is_peeking (bool)
            ignore_list (list): list of users to ignore
        """
        if not event.is_state() and event.sender in ignore_list:
            return False

        state = event_id_to_state[event.event_id]

        # get the room_visibility at the time of the event.
        visibility_event = state.get((EventTypes.RoomHistoryVisibility, ""), None)
        if visibility_event:
            visibility = visibility_event.content.get("history_visibility", "shared")
        else:
            visibility = "shared"

        if visibility not in VISIBILITY_PRIORITY:
            visibility = "shared"

        # if it was world_readable, it's easy: everyone can read it
        if visibility == "world_readable":
            return True

        # Always allow history visibility events on boundaries. This is done
        # by setting the effective visibility to the least restrictive
        # of the old vs new.
        if event.type == EventTypes.RoomHistoryVisibility:
            prev_content = event.unsigned.get("prev_content", {})
            prev_visibility = prev_content.get("history_visibility", None)

            if prev_visibility not in VISIBILITY_PRIORITY:
                prev_visibility = "shared"

            new_priority = VISIBILITY_PRIORITY.index(visibility)
            old_priority = VISIBILITY_PRIORITY.index(prev_visibility)
            if old_priority < new_priority:
                visibility = prev_visibility

        # likewise, if the event is the user's own membership event, use
        # the 'most joined' membership
        membership = None
        if event.type == EventTypes.Member and event.state_key == user_id:
            membership = event.content.get("membership", None)
            if membership not in MEMBERSHIP_PRIORITY:
                membership = "leave"

            prev_content = event.unsigned.get("prev_content", {})
            prev_membership = prev_content.get("membership", None)
            if prev_membership not in MEMBERSHIP_PRIORITY:
                prev_membership = "leave"

            # Always allow the user to see their own leave events, otherwise
            # they won't see the room disappear if they reject the invite
            if membership == "leave" and (
                prev_membership == "join" or prev_membership == "invite"
            ):
                return True

            new_priority = MEMBERSHIP_PRIORITY.index(membership)
            old_priority = MEMBERSHIP_PRIORITY.index(prev_membership)
            if old_priority < new_priority:
                membership = prev_membership

        # otherwise, get the user's membership at the time of the event.
        if membership is None:
            membership_event = state.get((EventTypes.Member, user_id), None)
            if membership_event:
                if membership_event.event_id not in event_id_forgotten:
                    membership = membership_event.membership

        # if the user was a member of the room at the time of the event,
        # they can see it.
        if membership == Membership.JOIN:
            return True

        if visibility == "joined":
            # we weren't a member at the time of the event, so we can't
            # see this event.
            return False

        elif visibility == "invited":
            # user can also see the event if they were *invited* at the time
            # of the event.
            return membership == Membership.INVITE

        else:
            # visibility is shared: user can also see the event if they have
            # become a member since the event
            #
            # XXX: if the user has subsequently joined and then left again,
            # ideally we would share history up to the point they left. But
            # we don't know when they left.
            return not is_peeking

    defer.returnValue({
        user_id: [
            event
            for event in events
            if allowed(event, user_id, is_peeking, ignore_dict.get(user_id, []))
        ]
        for user_id, is_peeking in user_tuples
    })


@defer.inlineCallbacks
def filter_events_for_client(store, user_id, events, is_peeking=False):
    """
    Check which events a user is allowed to see

    Args:
        user_id(str): user id to be checked
        events([synapse.events.EventBase]): list of events to be checked
        is_peeking(bool): should be True if:
          * the user is not currently a member of the room, and:
          * the user has not been a member of the room since the given
            events

    Returns:
        [synapse.events.EventBase]
    """
    types = (
        (EventTypes.RoomHistoryVisibility, ""),
        (EventTypes.Member, user_id),
    )
    event_id_to_state = yield store.get_state_for_events(
        frozenset(e.event_id for e in events),
        types=types
    )
    res = yield filter_events_for_clients(
        store, [(user_id, is_peeking)], events, event_id_to_state
    )
    defer.returnValue(res.get(user_id, []))
