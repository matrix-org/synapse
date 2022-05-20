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
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import attr
from prometheus_client import Counter

from synapse.api.constants import EventTypes, Membership, RelationTypes
from synapse.event_auth import auth_types_for_event, get_user_power_level
from synapse.events import EventBase, relation_from_event
from synapse.events.snapshot import EventContext
from synapse.state import POWER_KEY
from synapse.storage.databases.main.roommember import EventIdMembership
from synapse.util.async_helpers import Linearizer
from synapse.util.caches import CacheMetric, register_cache
from synapse.util.caches.descriptors import lru_cache
from synapse.util.caches.lrucache import LruCache
from synapse.util.metrics import measure_func

from ..storage.state import StateFilter
from .push_rule_evaluator import PushRuleEvaluatorForEvent

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


push_rules_invalidation_counter = Counter(
    "synapse_push_bulk_push_rule_evaluator_push_rules_invalidation_counter", ""
)
push_rules_state_size_counter = Counter(
    "synapse_push_bulk_push_rule_evaluator_push_rules_state_size_counter", ""
)

# Measures whether we use the fast path of using state deltas, or if we have to
# recalculate from scratch
push_rules_delta_state_cache_metric = register_cache(
    "cache",
    "push_rules_delta_state_cache_metric",
    cache=[],  # Meaningless size, as this isn't a cache that stores values
    resizable=False,
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

        # Used by `RulesForRoom` to ensure only one thing mutates the cache at a
        # time. Keyed off room_id.
        self._rules_linearizer = Linearizer(name="rules_for_room")

        self.room_push_rule_cache_metrics = register_cache(
            "cache",
            "room_push_rule_cache",
            cache=[],  # Meaningless size, as this isn't a cache that stores values,
            resizable=False,
        )

        # Whether to support MSC3772 is supported.
        self._relations_match_enabled = self.hs.config.experimental.msc3772_enabled

    async def _get_rules_for_event(
        self, event: EventBase, context: EventContext
    ) -> Dict[str, List[Dict[str, Any]]]:
        """This gets the rules for all users in the room at the time of the event,
        as well as the push rules for the invitee if the event is an invite.

        Returns:
            dict of user_id -> push_rules
        """
        room_id = event.room_id

        rules_for_room_data = self._get_rules_for_room(room_id)
        rules_for_room = RulesForRoom(
            hs=self.hs,
            room_id=room_id,
            rules_for_room_cache=self._get_rules_for_room.cache,
            room_push_rule_cache_metrics=self.room_push_rule_cache_metrics,
            linearizer=self._rules_linearizer,
            cached_data=rules_for_room_data,
        )

        rules_by_user = await rules_for_room.get_rules(event, context)

        # if this event is an invite event, we may need to run rules for the user
        # who's been invited, otherwise they won't get told they've been invited
        if event.type == "m.room.member" and event.content["membership"] == "invite":
            invited = event.state_key
            if invited and self.hs.is_mine_id(invited):
                rules_by_user = dict(rules_by_user)
                rules_by_user[invited] = await self.store.get_push_rules_for_user(
                    invited
                )

        return rules_by_user

    @lru_cache()
    def _get_rules_for_room(self, room_id: str) -> "RulesForRoomData":
        """Get the current RulesForRoomData object for the given room id"""
        # It's important that the RulesForRoomData object gets added to self._get_rules_for_room.cache
        # before any lookup methods get called on it as otherwise there may be
        # a race if invalidate_all gets called (which assumes its in the cache)
        return RulesForRoomData()

    async def _get_power_levels_and_sender_level(
        self, event: EventBase, context: EventContext
    ) -> Tuple[dict, int]:
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
        self, event: EventBase, rules: Iterable[Dict[str, Any]]
    ) -> Dict[str, Set[Tuple[str, str]]]:
        """
        Fetch event metadata for events which related to the same event as the given event.

        If the given event has no relation information, returns an empty dictionary.

        Args:
            event_id: The event ID which is targeted by relations.
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

        # If the event does not have a relation, then cannot have any mutual
        # relations.
        relation = relation_from_event(event)
        if not relation:
            return {}

        # Pre-filter to figure out which relation types are interesting.
        rel_types = set()
        for rule in rules:
            # Skip disabled rules.
            if "enabled" in rule and not rule["enabled"]:
                continue

            for condition in rule["conditions"]:
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
        return await self.store.get_mutual_event_relations(
            relation.parent_id, rel_types
        )

    @measure_func("action_for_event_by_user")
    async def action_for_event_by_user(
        self, event: EventBase, context: EventContext
    ) -> None:
        """Given an event and context, evaluate the push rules, check if the message
        should increment the unread count, and insert the results into the
        event_push_actions_staging table.
        """
        if event.internal_metadata.is_outlier():
            # This can happen due to out of band memberships
            return

        count_as_unread = _should_count_as_unread(event, context)

        rules_by_user = await self._get_rules_for_event(event, context)
        actions_by_user: Dict[str, List[Union[dict, str]]] = {}

        room_members = await self.store.get_joined_users_from_context(event, context)

        (
            power_levels,
            sender_power_level,
        ) = await self._get_power_levels_and_sender_level(event, context)

        relations = await self._get_mutual_relations(
            event, itertools.chain(*rules_by_user.values())
        )

        evaluator = PushRuleEvaluatorForEvent(
            event,
            len(room_members),
            sender_power_level,
            power_levels,
            relations,
            self._relations_match_enabled,
        )

        # If the event is not a state event check if any users ignore the sender.
        if not event.is_state():
            ignorers = await self.store.ignored_by(event.sender)
        else:
            ignorers = frozenset()

        for uid, rules in rules_by_user.items():
            if event.sender == uid:
                continue

            if uid in ignorers:
                continue

            display_name = None
            profile_info = room_members.get(uid)
            if profile_info:
                display_name = profile_info.display_name

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

            for rule in rules:
                if "enabled" in rule and not rule["enabled"]:
                    continue

                matches = evaluator.check_conditions(
                    rule["conditions"], uid, display_name
                )
                if matches:
                    actions = [x for x in rule["actions"] if x != "dont_notify"]
                    if actions and "notify" in actions:
                        # Push rules say we should notify the user of this event
                        actions_by_user[uid] = actions
                    break

        # Mark in the DB staging area the push actions for users who should be
        # notified for this event. (This will then get handled when we persist
        # the event)
        await self.store.add_push_actions_to_staging(
            event.event_id,
            actions_by_user,
            count_as_unread,
        )


MemberMap = Dict[str, Optional[EventIdMembership]]
Rule = Dict[str, dict]
RulesByUser = Dict[str, List[Rule]]
StateGroup = Union[object, int]


@attr.s(slots=True, auto_attribs=True)
class RulesForRoomData:
    """The data stored in the cache by `RulesForRoom`.

    We don't store `RulesForRoom` directly in the cache as we want our caches to
    *only* include data, and not references to e.g. the data stores.
    """

    # event_id -> EventIdMembership
    member_map: MemberMap = attr.Factory(dict)
    # user_id -> rules
    rules_by_user: RulesByUser = attr.Factory(dict)

    # The last state group we updated the caches for. If the state_group of
    # a new event comes along, we know that we can just return the cached
    # result.
    # On invalidation of the rules themselves (if the user changes them),
    # we invalidate everything and set state_group to `object()`
    state_group: StateGroup = attr.Factory(object)

    # A sequence number to keep track of when we're allowed to update the
    # cache. We bump the sequence number when we invalidate the cache. If
    # the sequence number changes while we're calculating stuff we should
    # not update the cache with it.
    sequence: int = 0

    # A cache of user_ids that we *know* aren't interesting, e.g. user_ids
    # owned by AS's, or remote users, etc. (I.e. users we will never need to
    # calculate push for)
    # These never need to be invalidated as we will never set up push for
    # them.
    uninteresting_user_set: Set[str] = attr.Factory(set)


class RulesForRoom:
    """Caches push rules for users in a room.

    This efficiently handles users joining/leaving the room by not invalidating
    the entire cache for the room.

    A new instance is constructed for each call to
    `BulkPushRuleEvaluator._get_rules_for_event`, with the cached data from
    previous calls passed in.
    """

    def __init__(
        self,
        hs: "HomeServer",
        room_id: str,
        rules_for_room_cache: LruCache,
        room_push_rule_cache_metrics: CacheMetric,
        linearizer: Linearizer,
        cached_data: RulesForRoomData,
    ):
        """
        Args:
            hs: The HomeServer object.
            room_id: The room ID.
            rules_for_room_cache: The cache object that caches these
                RoomsForUser objects.
            room_push_rule_cache_metrics: The metrics object
            linearizer: The linearizer used to ensure only one thing mutates
                the cache at a time. Keyed off room_id
            cached_data: Cached data from previous calls to `self.get_rules`,
                can be mutated.
        """
        self.room_id = room_id
        self.is_mine_id = hs.is_mine_id
        self.store = hs.get_datastores().main
        self.room_push_rule_cache_metrics = room_push_rule_cache_metrics

        # Used to ensure only one thing mutates the cache at a time. Keyed off
        # room_id.
        self.linearizer = linearizer

        self.data = cached_data

        # We need to be clever on the invalidating caches callbacks, as
        # otherwise the invalidation callback holds a reference to the object,
        # potentially causing it to leak.
        # To get around this we pass a function that on invalidations looks ups
        # the RoomsForUser entry in the cache, rather than keeping a reference
        # to self around in the callback.
        self.invalidate_all_cb = _Invalidation(rules_for_room_cache, room_id)

    async def get_rules(
        self, event: EventBase, context: EventContext
    ) -> Dict[str, List[Dict[str, dict]]]:
        """Given an event context return the rules for all users who are
        currently in the room.
        """
        state_group = context.state_group

        if state_group and self.data.state_group == state_group:
            logger.debug("Using cached rules for %r", self.room_id)
            self.room_push_rule_cache_metrics.inc_hits()
            return self.data.rules_by_user

        async with self.linearizer.queue(self.room_id):
            if state_group and self.data.state_group == state_group:
                logger.debug("Using cached rules for %r", self.room_id)
                self.room_push_rule_cache_metrics.inc_hits()
                return self.data.rules_by_user

            local_users = await self.store.get_local_users_in_room(
                self.room_id, on_invalidate=self.invalidate_all_cb
            )

            if event.type == EventTypes.Member and event.membership == Membership.JOIN:
                if self.is_mine_id(event.state_key):
                    local_users = list(local_users)
                    local_users.append(event.state_key)

            ret_rules_by_user = await self.store.bulk_get_push_rules(
                local_users, on_invalidate=self.invalidate_all_cb
            )

            logger.debug("Users in room: %s", local_users)

            self.update_cache(
                self.data.sequence,
                members={},  # There were no membership changes
                rules_by_user=ret_rules_by_user,
                state_group=state_group,
            )

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Returning push rules for %r %r", self.room_id, ret_rules_by_user.keys()
            )
        return ret_rules_by_user

    def update_cache(
        self,
        sequence: int,
        members: MemberMap,
        rules_by_user: RulesByUser,
        state_group: StateGroup,
    ) -> None:
        if sequence == self.data.sequence:
            self.data.member_map.update(members)
            self.data.rules_by_user = rules_by_user
            self.data.state_group = state_group


@attr.attrs(slots=True, frozen=True, auto_attribs=True)
class _Invalidation:
    # _Invalidation is passed as an `on_invalidate` callback to bulk_get_push_rules,
    # which means that it it is stored on the bulk_get_push_rules cache entry. In order
    # to ensure that we don't accumulate lots of redundant callbacks on the cache entry,
    # we need to ensure that two _Invalidation objects are "equal" if they refer to the
    # same `cache` and `room_id`.
    #
    # attrs provides suitable __hash__ and __eq__ methods, provided we remember to
    # set `frozen=True`.

    cache: LruCache
    room_id: str

    def __call__(self) -> None:
        rules_data = self.cache.get(self.room_id, None, update_metrics=False)
        if rules_data:
            rules_data.sequence += 1
            rules_data.state_group = object()
            rules_data.member_map = {}
            rules_data.rules_by_user = {}
            push_rules_invalidation_counter.inc()
