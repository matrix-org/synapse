# -*- coding: utf-8 -*-
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

import logging
from collections import namedtuple

from six import iteritems, itervalues

from prometheus_client import Counter

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.event_auth import get_user_power_level
from synapse.state import POWER_KEY
from synapse.util.async_helpers import Linearizer
from synapse.util.caches import register_cache
from synapse.util.caches.descriptors import cached

from .push_rule_evaluator import PushRuleEvaluatorForEvent

logger = logging.getLogger(__name__)


rules_by_room = {}


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


class BulkPushRuleEvaluator(object):
    """Calculates the outcome of push rules for an event for all users in the
    room at once.
    """

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

        self.room_push_rule_cache_metrics = register_cache(
            "cache",
            "room_push_rule_cache",
            cache=[],  # Meaningless size, as this isn't a cache that stores values,
            resizable=False,
        )

    @defer.inlineCallbacks
    def _get_rules_for_event(self, event, context):
        """This gets the rules for all users in the room at the time of the event,
        as well as the push rules for the invitee if the event is an invite.

        Returns:
            dict of user_id -> push_rules
        """
        room_id = event.room_id
        rules_for_room = yield self._get_rules_for_room(room_id)

        rules_by_user = yield rules_for_room.get_rules(event, context)

        # if this event is an invite event, we may need to run rules for the user
        # who's been invited, otherwise they won't get told they've been invited
        if event.type == "m.room.member" and event.content["membership"] == "invite":
            invited = event.state_key
            if invited and self.hs.is_mine_id(invited):
                has_pusher = yield self.store.user_has_pusher(invited)
                if has_pusher:
                    rules_by_user = dict(rules_by_user)
                    rules_by_user[invited] = yield self.store.get_push_rules_for_user(
                        invited
                    )

        return rules_by_user

    @cached()
    def _get_rules_for_room(self, room_id):
        """Get the current RulesForRoom object for the given room id

        Returns:
            RulesForRoom
        """
        # It's important that RulesForRoom gets added to self._get_rules_for_room.cache
        # before any lookup methods get called on it as otherwise there may be
        # a race if invalidate_all gets called (which assumes its in the cache)
        return RulesForRoom(
            self.hs,
            room_id,
            self._get_rules_for_room.cache,
            self.room_push_rule_cache_metrics,
        )

    @defer.inlineCallbacks
    def _get_power_levels_and_sender_level(self, event, context):
        prev_state_ids = yield context.get_prev_state_ids()
        pl_event_id = prev_state_ids.get(POWER_KEY)
        if pl_event_id:
            # fastpath: if there's a power level event, that's all we need, and
            # not having a power level event is an extreme edge case
            pl_event = yield self.store.get_event(pl_event_id)
            auth_events = {POWER_KEY: pl_event}
        else:
            auth_events_ids = yield self.auth.compute_auth_events(
                event, prev_state_ids, for_verification=False
            )
            auth_events = yield self.store.get_events(auth_events_ids)
            auth_events = {(e.type, e.state_key): e for e in itervalues(auth_events)}

        sender_level = get_user_power_level(event.sender, auth_events)

        pl_event = auth_events.get(POWER_KEY)

        return pl_event.content if pl_event else {}, sender_level

    @defer.inlineCallbacks
    def action_for_event_by_user(self, event, context):
        """Given an event and context, evaluate the push rules and insert the
        results into the event_push_actions_staging table.

        Returns:
            Deferred
        """
        rules_by_user = yield self._get_rules_for_event(event, context)
        actions_by_user = {}

        room_members = yield self.store.get_joined_users_from_context(event, context)

        (
            power_levels,
            sender_power_level,
        ) = yield self._get_power_levels_and_sender_level(event, context)

        evaluator = PushRuleEvaluatorForEvent(
            event, len(room_members), sender_power_level, power_levels
        )

        condition_cache = {}

        for uid, rules in iteritems(rules_by_user):
            if event.sender == uid:
                continue

            if not event.is_state():
                is_ignored = yield self.store.is_ignored_by(event.sender, uid)
                if is_ignored:
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

            for rule in rules:
                if "enabled" in rule and not rule["enabled"]:
                    continue

                matches = _condition_checker(
                    evaluator, rule["conditions"], uid, display_name, condition_cache
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
        yield self.store.add_push_actions_to_staging(event.event_id, actions_by_user)


def _condition_checker(evaluator, conditions, uid, display_name, cache):
    for cond in conditions:
        _id = cond.get("_id", None)
        if _id:
            res = cache.get(_id, None)
            if res is False:
                return False
            elif res is True:
                continue

        res = evaluator.matches(cond, uid, display_name)
        if _id:
            cache[_id] = bool(res)

        if not res:
            return False

    return True


class RulesForRoom(object):
    """Caches push rules for users in a room.

    This efficiently handles users joining/leaving the room by not invalidating
    the entire cache for the room.
    """

    def __init__(self, hs, room_id, rules_for_room_cache, room_push_rule_cache_metrics):
        """
        Args:
            hs (HomeServer)
            room_id (str)
            rules_for_room_cache(Cache): The cache object that caches these
                RoomsForUser objects.
            room_push_rule_cache_metrics (CacheMetric)
        """
        self.room_id = room_id
        self.is_mine_id = hs.is_mine_id
        self.store = hs.get_datastore()
        self.room_push_rule_cache_metrics = room_push_rule_cache_metrics

        self.linearizer = Linearizer(name="rules_for_room")

        self.member_map = {}  # event_id -> (user_id, state)
        self.rules_by_user = {}  # user_id -> rules

        # The last state group we updated the caches for. If the state_group of
        # a new event comes along, we know that we can just return the cached
        # result.
        # On invalidation of the rules themselves (if the user changes them),
        # we invalidate everything and set state_group to `object()`
        self.state_group = object()

        # A sequence number to keep track of when we're allowed to update the
        # cache. We bump the sequence number when we invalidate the cache. If
        # the sequence number changes while we're calculating stuff we should
        # not update the cache with it.
        self.sequence = 0

        # A cache of user_ids that we *know* aren't interesting, e.g. user_ids
        # owned by AS's, or remote users, etc. (I.e. users we will never need to
        # calculate push for)
        # These never need to be invalidated as we will never set up push for
        # them.
        self.uninteresting_user_set = set()

        # We need to be clever on the invalidating caches callbacks, as
        # otherwise the invalidation callback holds a reference to the object,
        # potentially causing it to leak.
        # To get around this we pass a function that on invalidations looks ups
        # the RoomsForUser entry in the cache, rather than keeping a reference
        # to self around in the callback.
        self.invalidate_all_cb = _Invalidation(rules_for_room_cache, room_id)

    @defer.inlineCallbacks
    def get_rules(self, event, context):
        """Given an event context return the rules for all users who are
        currently in the room.
        """
        state_group = context.state_group

        if state_group and self.state_group == state_group:
            logger.debug("Using cached rules for %r", self.room_id)
            self.room_push_rule_cache_metrics.inc_hits()
            return self.rules_by_user

        with (yield self.linearizer.queue(())):
            if state_group and self.state_group == state_group:
                logger.debug("Using cached rules for %r", self.room_id)
                self.room_push_rule_cache_metrics.inc_hits()
                return self.rules_by_user

            self.room_push_rule_cache_metrics.inc_misses()

            ret_rules_by_user = {}
            missing_member_event_ids = {}
            if state_group and self.state_group == context.prev_group:
                # If we have a simple delta then we can reuse most of the previous
                # results.
                ret_rules_by_user = self.rules_by_user
                current_state_ids = context.delta_ids

                push_rules_delta_state_cache_metric.inc_hits()
            else:
                current_state_ids = yield context.get_current_state_ids()
                push_rules_delta_state_cache_metric.inc_misses()

            push_rules_state_size_counter.inc(len(current_state_ids))

            logger.debug(
                "Looking for member changes in %r %r", state_group, current_state_ids
            )

            # Loop through to see which member events we've seen and have rules
            # for and which we need to fetch
            for key in current_state_ids:
                typ, user_id = key
                if typ != EventTypes.Member:
                    continue

                if user_id in self.uninteresting_user_set:
                    continue

                if not self.is_mine_id(user_id):
                    self.uninteresting_user_set.add(user_id)
                    continue

                if self.store.get_if_app_services_interested_in_user(user_id):
                    self.uninteresting_user_set.add(user_id)
                    continue

                event_id = current_state_ids[key]

                res = self.member_map.get(event_id, None)
                if res:
                    user_id, state = res
                    if state == Membership.JOIN:
                        rules = self.rules_by_user.get(user_id, None)
                        if rules:
                            ret_rules_by_user[user_id] = rules
                    continue

                # If a user has left a room we remove their push rule. If they
                # joined then we readd it later in _update_rules_with_member_event_ids
                ret_rules_by_user.pop(user_id, None)
                missing_member_event_ids[user_id] = event_id

            if missing_member_event_ids:
                # If we have some memebr events we haven't seen, look them up
                # and fetch push rules for them if appropriate.
                logger.debug("Found new member events %r", missing_member_event_ids)
                yield self._update_rules_with_member_event_ids(
                    ret_rules_by_user, missing_member_event_ids, state_group, event
                )
            else:
                # The push rules didn't change but lets update the cache anyway
                self.update_cache(
                    self.sequence,
                    members={},  # There were no membership changes
                    rules_by_user=ret_rules_by_user,
                    state_group=state_group,
                )

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Returning push rules for %r %r", self.room_id, ret_rules_by_user.keys()
            )
        return ret_rules_by_user

    @defer.inlineCallbacks
    def _update_rules_with_member_event_ids(
        self, ret_rules_by_user, member_event_ids, state_group, event
    ):
        """Update the partially filled rules_by_user dict by fetching rules for
        any newly joined users in the `member_event_ids` list.

        Args:
            ret_rules_by_user (dict): Partiallly filled dict of push rules. Gets
                updated with any new rules.
            member_event_ids (list): List of event ids for membership events that
                have happened since the last time we filled rules_by_user
            state_group: The state group we are currently computing push rules
                for. Used when updating the cache.
        """
        sequence = self.sequence

        rows = yield self.store.get_membership_from_event_ids(member_event_ids.values())

        members = {row["event_id"]: (row["user_id"], row["membership"]) for row in rows}

        # If the event is a join event then it will be in current state evnts
        # map but not in the DB, so we have to explicitly insert it.
        if event.type == EventTypes.Member:
            for event_id in itervalues(member_event_ids):
                if event_id == event.event_id:
                    members[event_id] = (event.state_key, event.membership)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Found members %r: %r", self.room_id, members.values())

        interested_in_user_ids = {
            user_id
            for user_id, membership in itervalues(members)
            if membership == Membership.JOIN
        }

        logger.debug("Joined: %r", interested_in_user_ids)

        if_users_with_pushers = yield self.store.get_if_users_have_pushers(
            interested_in_user_ids, on_invalidate=self.invalidate_all_cb
        )

        user_ids = {
            uid for uid, have_pusher in iteritems(if_users_with_pushers) if have_pusher
        }

        logger.debug("With pushers: %r", user_ids)

        users_with_receipts = yield self.store.get_users_with_read_receipts_in_room(
            self.room_id, on_invalidate=self.invalidate_all_cb
        )

        logger.debug("With receipts: %r", users_with_receipts)

        # any users with pushers must be ours: they have pushers
        for uid in users_with_receipts:
            if uid in interested_in_user_ids:
                user_ids.add(uid)

        rules_by_user = yield self.store.bulk_get_push_rules(
            user_ids, on_invalidate=self.invalidate_all_cb
        )

        ret_rules_by_user.update(
            item for item in iteritems(rules_by_user) if item[0] is not None
        )

        self.update_cache(sequence, members, ret_rules_by_user, state_group)

    def invalidate_all(self):
        # Note: Don't hand this function directly to an invalidation callback
        # as it keeps a reference to self and will stop this instance from being
        # GC'd if it gets dropped from the rules_to_user cache. Instead use
        # `self.invalidate_all_cb`
        logger.debug("Invalidating RulesForRoom for %r", self.room_id)
        self.sequence += 1
        self.state_group = object()
        self.member_map = {}
        self.rules_by_user = {}
        push_rules_invalidation_counter.inc()

    def update_cache(self, sequence, members, rules_by_user, state_group):
        if sequence == self.sequence:
            self.member_map.update(members)
            self.rules_by_user = rules_by_user
            self.state_group = state_group


class _Invalidation(namedtuple("_Invalidation", ("cache", "room_id"))):
    # We rely on _CacheContext implementing __eq__ and __hash__ sensibly,
    # which namedtuple does for us (i.e. two _CacheContext are the same if
    # their caches and keys match). This is important in particular to
    # dedupe when we add callbacks to lru cache nodes, otherwise the number
    # of callbacks would grow.
    def __call__(self):
        rules = self.cache.get(self.room_id, None, update_metrics=False)
        if rules:
            rules.invalidate_all()
