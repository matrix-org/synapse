# Copyright 2015 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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

import itertools
import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
    Union,
)

from prometheus_client import Counter

from synapse.api.constants import EventTypes, Membership, RelationTypes
from synapse.event_auth import auth_types_for_event, get_user_power_level
from synapse.events import EventBase, relation_from_event
from synapse.events.snapshot import EventContext
from synapse.state import POWER_KEY
from synapse.storage.databases.main.roommember import EventIdMembership
from synapse.storage.state import StateFilter
from synapse.synapse_rust.push import FilteredPushRules, PushRule, PushRuleEvaluator
from synapse.util.caches import register_cache
from synapse.util.metrics import measure_func
from synapse.visibility import filter_event_for_clients_with_state

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


push_rules_invalidation_counter = Counter(
    "synapse_push_bulk_push_rule_evaluator_push_rules_invalidation_counter", ""
)
push_rules_state_size_counter = Counter(
    "synapse_push_bulk_push_rule_evaluator_push_rules_state_size_counter", ""
)


STATE_EVENT_TYPES_TO_MARK_UNREAD = {
    EventTypes.Topic,
    EventTypes.Name,
    EventTypes.RoomAvatar,
    EventTypes.Tombstone,
}


def _should_count_as_unread(event: EventBase, context: EventContext) -> bool:
    # Exclude rejected and soft-failed events.
    if context.rejected or event.internal_metadata.is_soft_failed():
        return False

    # Exclude notices.
    if (
        not event.is_state()
        and event.type == EventTypes.Message
        and event.content.get("msgtype") == "m.notice"
    ):
        return False

    # Exclude edits.
    relates_to = relation_from_event(event)
    if relates_to and relates_to.rel_type == RelationTypes.REPLACE:
        return False

    # Mark events that have a non-empty string body as unread.
    body = event.content.get("body")
    if isinstance(body, str) and body:
        return True

    # Mark some state events as unread.
    if event.is_state() and event.type in STATE_EVENT_TYPES_TO_MARK_UNREAD:
        return True

    # Mark encrypted events as unread.
    if not event.is_state() and event.type == EventTypes.Encrypted:
        return True

    return False


class BulkPushRuleEvaluator:
    """Calculates the outcome of push rules for an event for all users in the
    room at once.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self._event_auth_handler = hs.get_event_auth_handler()

        self.room_push_rule_cache_metrics = register_cache(
            "cache",
            "room_push_rule_cache",
            cache=[],  # Meaningless size, as this isn't a cache that stores values,
            resizable=False,
        )

        # Whether to support MSC3772 is supported.
        self._relations_match_enabled = self.hs.config.experimental.msc3772_enabled

    async def _get_rules_for_event(
        self,
        event: EventBase,
    ) -> Dict[str, FilteredPushRules]:
        """Get the push rules for all users who may need to be notified about
        the event.

        Note: this does not check if the user is allowed to see the event.

        Returns:
            Mapping of user ID to their push rules.
        """
        # We get the users who may need to be notified by first fetching the
        # local users currently in the room, finding those that have push rules,
        # and *then* checking which users are actually allowed to see the event.
        #
        # The alternative is to first fetch all users that were joined at the
        # event, but that requires fetching the full state at the event, which
        # may be expensive for large rooms with few local users.

        local_users = await self.store.get_local_users_in_room(event.room_id)

        # Filter out appservice users.
        local_users = [
            u
            for u in local_users
            if not self.store.get_if_app_services_interested_in_user(u)
        ]

        # if this event is an invite event, we may need to run rules for the user
        # who's been invited, otherwise they won't get told they've been invited
        if event.type == EventTypes.Member and event.membership == Membership.INVITE:
            invited = event.state_key
            if invited and self.hs.is_mine_id(invited) and invited not in local_users:
                local_users = list(local_users)
                local_users.append(invited)

        rules_by_user = await self.store.bulk_get_push_rules(local_users)

        logger.debug("Users in room: %s", local_users)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Returning push rules for %r %r",
                event.room_id,
                list(rules_by_user.keys()),
            )

        return rules_by_user

    async def _get_power_levels_and_sender_level(
        self, event: EventBase, context: EventContext
    ) -> Tuple[dict, Optional[int]]:
        # There are no power levels and sender levels possible to get from outlier
        if event.internal_metadata.is_outlier():
            return {}, None

        event_types = auth_types_for_event(event.room_version, event)
        prev_state_ids = await context.get_prev_state_ids(
            StateFilter.from_types(event_types)
        )
        pl_event_id = prev_state_ids.get(POWER_KEY)

        if pl_event_id:
            # fastpath: if there's a power level event, that's all we need, and
            # not having a power level event is an extreme edge case
            auth_events = {POWER_KEY: await self.store.get_event(pl_event_id)}
        else:
            auth_events_ids = self._event_auth_handler.compute_auth_events(
                event, prev_state_ids, for_verification=False
            )
            auth_events_dict = await self.store.get_events(auth_events_ids)
            auth_events = {(e.type, e.state_key): e for e in auth_events_dict.values()}

        sender_level = get_user_power_level(event.sender, auth_events)

        pl_event = auth_events.get(POWER_KEY)

        return pl_event.content if pl_event else {}, sender_level

    async def _get_mutual_relations(
        self, parent_id: str, rules: Iterable[Tuple[PushRule, bool]]
    ) -> Dict[str, Set[Tuple[str, str]]]:
        """
        Fetch event metadata for events which related to the same event as the given event.

        If the given event has no relation information, returns an empty dictionary.

        Args:
            parent_id: The event ID which is targeted by relations.
            rules: The push rules which will be processed for this event.

        Returns:
            A dictionary of relation type to:
                A set of tuples of:
                    The sender
                    The event type
        """

        # If the experimental feature is not enabled, skip fetching relations.
        if not self._relations_match_enabled:
            return {}

        # Pre-filter to figure out which relation types are interesting.
        rel_types = set()
        for rule, enabled in rules:
            if not enabled:
                continue

            for condition in rule.conditions:
                if condition["kind"] != "org.matrix.msc3772.relation_match":
                    continue

                # rel_type is required.
                rel_type = condition.get("rel_type")
                if rel_type:
                    rel_types.add(rel_type)

        # If no valid rules were found, no mutual relations.
        if not rel_types:
            return {}

        # If any valid rules were found, fetch the mutual relations.
        return await self.store.get_mutual_event_relations(parent_id, rel_types)

    @measure_func("action_for_event_by_user")
    async def action_for_event_by_user(
        self, event: EventBase, context: EventContext
    ) -> None:
        """Given an event and context, evaluate the push rules, check if the message
        should increment the unread count, and insert the results into the
        event_push_actions_staging table.
        """
        if not event.internal_metadata.is_notifiable():
            # Push rules for events that aren't notifiable can't be processed by this
            return

        # Disable counting as unread unless the experimental configuration is
        # enabled, as it can cause additional (unwanted) rows to be added to the
        # event_push_actions table.
        count_as_unread = False
        if self.hs.config.experimental.msc2654_enabled:
            count_as_unread = _should_count_as_unread(event, context)

        rules_by_user = await self._get_rules_for_event(event)
        actions_by_user: Dict[str, Collection[Union[Mapping, str]]] = {}

        room_member_count = await self.store.get_number_joined_users_in_room(
            event.room_id
        )

        (
            power_levels,
            sender_power_level,
        ) = await self._get_power_levels_and_sender_level(event, context)

        relation = relation_from_event(event)
        # If the event does not have a relation, then cannot have any mutual
        # relations or thread ID.
        relations = {}
        thread_id = "main"
        if relation:
            relations = await self._get_mutual_relations(
                relation.parent_id,
                itertools.chain(*(r.rules() for r in rules_by_user.values())),
            )
            if relation.rel_type == RelationTypes.THREAD:
                thread_id = relation.parent_id

        # It's possible that old room versions have non-integer power levels (floats or
        # strings). Workaround this by explicitly converting to int.
        notification_levels = power_levels.get("notifications", {})
        if not event.room_version.msc3667_int_only_power_levels:
            for user_id, level in notification_levels.items():
                notification_levels[user_id] = int(level)

        evaluator = PushRuleEvaluator(
            _flatten_dict(event),
            room_member_count,
            sender_power_level,
            notification_levels,
            relations,
            self._relations_match_enabled,
        )

        users = rules_by_user.keys()
        profiles = await self.store.get_subset_users_in_room_with_profiles(
            event.room_id, users
        )

        for uid, rules in rules_by_user.items():
            if event.sender == uid:
                continue

            display_name = None
            profile = profiles.get(uid)
            if profile:
                display_name = profile.display_name

            if not display_name:
                # Handle the case where we are pushing a membership event to
                # that user, as they might not be already joined.
                if event.type == EventTypes.Member and event.state_key == uid:
                    display_name = event.content.get("displayname", None)
                    if not isinstance(display_name, str):
                        display_name = None

            if count_as_unread:
                # Add an element for the current user if the event needs to be marked as
                # unread, so that add_push_actions_to_staging iterates over it.
                # If the event shouldn't be marked as unread but should notify the
                # current user, it'll be added to the dict later.
                actions_by_user[uid] = []

            actions = evaluator.run(rules, uid, display_name)
            if "notify" in actions:
                # Push rules say we should notify the user of this event
                actions_by_user[uid] = actions

        # If there aren't any actions then we can skip the rest of the
        # processing.
        if not actions_by_user:
            return

        # This is a check for the case where user joins a room without being
        # allowed to see history, and then the server receives a delayed event
        # from before the user joined, which they should not be pushed for
        #
        # We do this *after* calculating the push actions as a) its unlikely
        # that we'll filter anyone out and b) for large rooms its likely that
        # most users will have push disabled and so the set of users to check is
        # much smaller.
        uids_with_visibility = await filter_event_for_clients_with_state(
            self.store, actions_by_user.keys(), event, context
        )

        for user_id in set(actions_by_user).difference(uids_with_visibility):
            actions_by_user.pop(user_id, None)

        # Mark in the DB staging area the push actions for users who should be
        # notified for this event. (This will then get handled when we persist
        # the event)
        await self.store.add_push_actions_to_staging(
            event.event_id,
            actions_by_user,
            count_as_unread,
            thread_id,
        )


MemberMap = Dict[str, Optional[EventIdMembership]]
Rule = Dict[str, dict]
RulesByUser = Dict[str, List[Rule]]
StateGroup = Union[object, int]


def _flatten_dict(
    d: Union[EventBase, Mapping[str, Any]],
    prefix: Optional[List[str]] = None,
    result: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    if prefix is None:
        prefix = []
    if result is None:
        result = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[".".join(prefix + [key])] = value.lower()
        elif isinstance(value, Mapping):
            _flatten_dict(value, prefix=(prefix + [key]), result=result)

    return result
