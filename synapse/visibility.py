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
import logging
import operator

from synapse.api.constants import (
    AccountDataTypes,
    EventTypes,
    HistoryVisibility,
    Membership,
)
from synapse.events.utils import prune_event
from synapse.storage import Storage
from synapse.storage.state import StateFilter
from synapse.types import get_domain_from_id

logger = logging.getLogger(__name__)


VISIBILITY_PRIORITY = (
    HistoryVisibility.WORLD_READABLE,
    HistoryVisibility.SHARED,
    HistoryVisibility.INVITED,
    HistoryVisibility.JOINED,
)


MEMBERSHIP_PRIORITY = (
    Membership.JOIN,
    Membership.INVITE,
    Membership.KNOCK,
    Membership.LEAVE,
    Membership.BAN,
)


async def filter_events_for_client(
    storage: Storage,
    user_id,
    events,
    is_peeking=False,
    always_include_ids=frozenset(),
    filter_send_to_client=True,
):
    """
    Check which events a user is allowed to see. If the user can see the event but its
    sender asked for their data to be erased, prune the content of the event.

    Args:
        storage
        user_id(str): user id to be checked
        events(list[synapse.events.EventBase]): sequence of events to be checked
        is_peeking(bool): should be True if:
          * the user is not currently a member of the room, and:
          * the user has not been a member of the room since the given
            events
        always_include_ids (set(event_id)): set of event ids to specifically
            include (unless sender is ignored)
        filter_send_to_client (bool): Whether we're checking an event that's going to be
            sent to a client. This might not always be the case since this function can
            also be called to check whether a user can see the state at a given point.

    Returns:
        list[synapse.events.EventBase]
    """
    # Filter out events that have been soft failed so that we don't relay them
    # to clients.
    events = [e for e in events if not e.internal_metadata.is_soft_failed()]

    types = ((EventTypes.RoomHistoryVisibility, ""), (EventTypes.Member, user_id))

    event_id_to_state = await storage.state.get_state_for_events(
        frozenset(e.event_id for e in events),
        state_filter=StateFilter.from_types(types),
    )

    ignore_dict_content = await storage.main.get_global_account_data_by_type_for_user(
        AccountDataTypes.IGNORED_USER_LIST, user_id
    )

    ignore_list = frozenset()
    if ignore_dict_content:
        ignored_users_dict = ignore_dict_content.get("ignored_users", {})
        if isinstance(ignored_users_dict, dict):
            ignore_list = frozenset(ignored_users_dict.keys())

    erased_senders = await storage.main.are_users_erased((e.sender for e in events))

    if filter_send_to_client:
        room_ids = {e.room_id for e in events}
        retention_policies = {}

        for room_id in room_ids:
            retention_policies[
                room_id
            ] = await storage.main.get_retention_policy_for_room(room_id)

    def allowed(event):
        """
        Args:
            event (synapse.events.EventBase): event to check

        Returns:
            None|EventBase:
               None if the user cannot see this event at all

               a redacted copy of the event if they can only see a redacted
               version

               the original event if they can see it as normal.
        """
        # Only run some checks if these events aren't about to be sent to clients. This is
        # because, if this is not the case, we're probably only checking if the users can
        # see events in the room at that point in the DAG, and that shouldn't be decided
        # on those checks.
        if filter_send_to_client:
            if event.type == EventTypes.Dummy:
                return None

            if not event.is_state() and event.sender in ignore_list:
                return None

            # Until MSC2261 has landed we can't redact malicious alias events, so for
            # now we temporarily filter out m.room.aliases entirely to mitigate
            # abuse, while we spec a better solution to advertising aliases
            # on rooms.
            if event.type == EventTypes.Aliases:
                return None

            # Don't try to apply the room's retention policy if the event is a state
            # event, as MSC1763 states that retention is only considered for non-state
            # events.
            if not event.is_state():
                retention_policy = retention_policies[event.room_id]
                max_lifetime = retention_policy.get("max_lifetime")

                if max_lifetime is not None:
                    oldest_allowed_ts = storage.main.clock.time_msec() - max_lifetime

                    if event.origin_server_ts < oldest_allowed_ts:
                        return None

        if event.event_id in always_include_ids:
            return event

        state = event_id_to_state[event.event_id]

        # get the room_visibility at the time of the event.
        visibility_event = state.get((EventTypes.RoomHistoryVisibility, ""), None)
        if visibility_event:
            visibility = visibility_event.content.get(
                "history_visibility", HistoryVisibility.SHARED
            )
        else:
            visibility = HistoryVisibility.SHARED

        if visibility not in VISIBILITY_PRIORITY:
            visibility = HistoryVisibility.SHARED

        # Always allow history visibility events on boundaries. This is done
        # by setting the effective visibility to the least restrictive
        # of the old vs new.
        if event.type == EventTypes.RoomHistoryVisibility:
            prev_content = event.unsigned.get("prev_content", {})
            prev_visibility = prev_content.get("history_visibility", None)

            if prev_visibility not in VISIBILITY_PRIORITY:
                prev_visibility = HistoryVisibility.SHARED

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
                return event

            new_priority = MEMBERSHIP_PRIORITY.index(membership)
            old_priority = MEMBERSHIP_PRIORITY.index(prev_membership)
            if old_priority < new_priority:
                membership = prev_membership

        # otherwise, get the user's membership at the time of the event.
        if membership is None:
            membership_event = state.get((EventTypes.Member, user_id), None)
            if membership_event:
                membership = membership_event.membership

        # if the user was a member of the room at the time of the event,
        # they can see it.
        if membership == Membership.JOIN:
            return event

        # otherwise, it depends on the room visibility.

        if visibility == HistoryVisibility.JOINED:
            # we weren't a member at the time of the event, so we can't
            # see this event.
            return None

        elif visibility == HistoryVisibility.INVITED:
            # user can also see the event if they were *invited* at the time
            # of the event.
            return event if membership == Membership.INVITE else None

        elif visibility == HistoryVisibility.SHARED and is_peeking:
            # if the visibility is shared, users cannot see the event unless
            # they have *subsequently* joined the room (or were members at the
            # time, of course)
            #
            # XXX: if the user has subsequently joined and then left again,
            # ideally we would share history up to the point they left. But
            # we don't know when they left. We just treat it as though they
            # never joined, and restrict access.
            return None

        # the visibility is either shared or world_readable, and the user was
        # not a member at the time. We allow it, provided the original sender
        # has not requested their data to be erased, in which case, we return
        # a redacted version.
        if erased_senders[event.sender]:
            return prune_event(event)

        return event

    # check each event: gives an iterable[None|EventBase]
    filtered_events = map(allowed, events)

    # remove the None entries
    filtered_events = filter(operator.truth, filtered_events)

    # we turn it into a list before returning it.
    return list(filtered_events)


async def filter_events_for_server(
    storage: Storage,
    server_name,
    events,
    redact=True,
    check_history_visibility_only=False,
):
    """Filter a list of events based on whether given server is allowed to
    see them.

    Args:
        storage
        server_name (str)
        events (iterable[FrozenEvent])
        redact (bool): Whether to return a redacted version of the event, or
            to filter them out entirely.
        check_history_visibility_only (bool): Whether to only check the
            history visibility, rather than things like if the sender has been
            erased. This is used e.g. during pagination to decide whether to
            backfill or not.

    Returns
        list[FrozenEvent]
    """

    def is_sender_erased(event, erased_senders):
        if erased_senders and erased_senders[event.sender]:
            logger.info("Sender of %s has been erased, redacting", event.event_id)
            return True
        return False

    def check_event_is_visible(event, state):
        history = state.get((EventTypes.RoomHistoryVisibility, ""), None)
        if history:
            visibility = history.content.get(
                "history_visibility", HistoryVisibility.SHARED
            )
            if visibility in [HistoryVisibility.INVITED, HistoryVisibility.JOINED]:
                # We now loop through all state events looking for
                # membership states for the requesting server to determine
                # if the server is either in the room or has been invited
                # into the room.
                for ev in state.values():
                    if ev.type != EventTypes.Member:
                        continue
                    try:
                        domain = get_domain_from_id(ev.state_key)
                    except Exception:
                        continue

                    if domain != server_name:
                        continue

                    memtype = ev.membership
                    if memtype == Membership.JOIN:
                        return True
                    elif memtype == Membership.INVITE:
                        if visibility == HistoryVisibility.INVITED:
                            return True
                else:
                    # server has no users in the room: redact
                    return False

        return True

    # Lets check to see if all the events have a history visibility
    # of "shared" or "world_readable". If that's the case then we don't
    # need to check membership (as we know the server is in the room).
    event_to_state_ids = await storage.state.get_state_ids_for_events(
        frozenset(e.event_id for e in events),
        state_filter=StateFilter.from_types(
            types=((EventTypes.RoomHistoryVisibility, ""),)
        ),
    )

    visibility_ids = set()
    for sids in event_to_state_ids.values():
        hist = sids.get((EventTypes.RoomHistoryVisibility, ""))
        if hist:
            visibility_ids.add(hist)

    # If we failed to find any history visibility events then the default
    # is "shared" visibility.
    if not visibility_ids:
        all_open = True
    else:
        event_map = await storage.main.get_events(visibility_ids)
        all_open = all(
            e.content.get("history_visibility")
            in (None, HistoryVisibility.SHARED, HistoryVisibility.WORLD_READABLE)
            for e in event_map.values()
        )

    if not check_history_visibility_only:
        erased_senders = await storage.main.are_users_erased((e.sender for e in events))
    else:
        # We don't want to check whether users are erased, which is equivalent
        # to no users having been erased.
        erased_senders = {}

    if all_open:
        # all the history_visibility state affecting these events is open, so
        # we don't need to filter by membership state. We *do* need to check
        # for user erasure, though.
        if erased_senders:
            to_return = []
            for e in events:
                if not is_sender_erased(e, erased_senders):
                    to_return.append(e)
                elif redact:
                    to_return.append(prune_event(e))

            return to_return

        # If there are no erased users then we can just return the given list
        # of events without having to copy it.
        return events

    # Ok, so we're dealing with events that have non-trivial visibility
    # rules, so we need to also get the memberships of the room.

    # first, for each event we're wanting to return, get the event_ids
    # of the history vis and membership state at those events.
    event_to_state_ids = await storage.state.get_state_ids_for_events(
        frozenset(e.event_id for e in events),
        state_filter=StateFilter.from_types(
            types=((EventTypes.RoomHistoryVisibility, ""), (EventTypes.Member, None))
        ),
    )

    # We only want to pull out member events that correspond to the
    # server's domain.
    #
    # event_to_state_ids contains lots of duplicates, so it turns out to be
    # cheaper to build a complete event_id => (type, state_key) dict, and then
    # filter out the ones we don't want
    #
    event_id_to_state_key = {
        event_id: key
        for key_to_eid in event_to_state_ids.values()
        for key, event_id in key_to_eid.items()
    }

    def include(typ, state_key):
        if typ != EventTypes.Member:
            return True

        # we avoid using get_domain_from_id here for efficiency.
        idx = state_key.find(":")
        if idx == -1:
            return False
        return state_key[idx + 1 :] == server_name

    event_map = await storage.main.get_events(
        [e_id for e_id, key in event_id_to_state_key.items() if include(key[0], key[1])]
    )

    event_to_state = {
        e_id: {
            key: event_map[inner_e_id]
            for key, inner_e_id in key_to_eid.items()
            if inner_e_id in event_map
        }
        for e_id, key_to_eid in event_to_state_ids.items()
    }

    to_return = []
    for e in events:
        erased = is_sender_erased(e, erased_senders)
        visible = check_event_is_visible(e, event_to_state[e.event_id])
        if visible and not erased:
            to_return.append(e)
        elif redact:
            to_return.append(prune_event(e))

    return to_return
