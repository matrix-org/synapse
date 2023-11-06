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
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)

from prometheus_client import Counter

from twisted.internet.defer import Deferred

from synapse.api.constants import (
    MAIN_TIMELINE,
    EventContentFields,
    EventTypes,
    Membership,
    RelationTypes,
)
from synapse.api.room_versions import PushRuleRoomFlag
from synapse.event_auth import auth_types_for_event, get_user_power_level
from synapse.events import EventBase, relation_from_event
from synapse.events.snapshot import EventContext
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.state import POWER_KEY
from synapse.storage.databases.main.roommember import EventIdMembership
from synapse.storage.roommember import ProfileInfo
from synapse.synapse_rust.push import FilteredPushRules, PushRuleEvaluator
from synapse.types import JsonValue
from synapse.types.state import StateFilter
from synapse.util import unwrapFirstError
from synapse.util.async_helpers import gather_results
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


SENTINEL = object()


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
        self.should_calculate_push_rules = self.hs.config.push.enable_push

        self._related_event_match_enabled = self.hs.config.experimental.msc3664_enabled

        self.room_push_rule_cache_metrics = register_cache(
            "cache",
            "room_push_rule_cache",
            cache=[],  # Meaningless size, as this isn't a cache that stores values,
            resizable=False,
        )

    async def _get_rules_for_event(
        self,
        event: EventBase,
    ) -> Mapping[str, FilteredPushRules]:
        """Get the push rules for all users who may need to be notified about
        the event.

        Note: this does not check if the user is allowed to see the event.

        Returns:
            Mapping of user ID to their push rules.
        """
        # If this is a membership event, only calculate push rules for the target.
        # While it's possible for users to configure push rules to respond to such an
        # event, in practise nobody does this. At the cost of violating the spec a
        # little, we can skip fetching a huge number of push rules in large rooms.
        # This helps make joins and leaves faster.
        if event.type == EventTypes.Member:
            local_users: Sequence[str] = []
            # We never notify a user about their own actions. This is enforced in
            # `_action_for_event_by_user` in the loop over `rules_by_user`, but we
            # do the same check here to avoid unnecessary DB queries.
            if event.sender != event.state_key and self.hs.is_mine_id(event.state_key):
                # Check the target is in the room, to avoid notifying them of
                # e.g. a pre-emptive ban.
                target_already_in_room = await self.store.check_local_user_in_room(
                    event.state_key, event.room_id
                )
                if target_already_in_room:
                    local_users = [event.state_key]
        else:
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
                local_users.append(invited)

        if not local_users:
            return {}

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
        self,
        event: EventBase,
        context: EventContext,
        event_id_to_event: Mapping[str, EventBase],
    ) -> Tuple[dict, Optional[int]]:
        """
        Given an event and an event context, get the power level event relevant to the event
        and the power level of the sender of the event.
        Args:
            event: event to check
            context: context of event to check
            event_id_to_event: a mapping of event_id to event for a set of events being
            batch persisted. This is needed as the sought-after power level event may
            be in this batch rather than the DB
        """
        # There are no power levels and sender levels possible to get from outlier
        if event.internal_metadata.is_outlier():
            return {}, None

        event_types = auth_types_for_event(event.room_version, event)
        prev_state_ids = await context.get_prev_state_ids(
            StateFilter.from_types(event_types)
        )
        pl_event_id = prev_state_ids.get(POWER_KEY)

        # fastpath: if there's a power level event, that's all we need, and
        # not having a power level event is an extreme edge case
        if pl_event_id:
            # Get the power level event from the batch, or fall back to the database.
            pl_event = event_id_to_event.get(pl_event_id)
            if pl_event:
                auth_events = {POWER_KEY: pl_event}
            else:
                auth_events = {POWER_KEY: await self.store.get_event(pl_event_id)}
        else:
            auth_events_ids = self._event_auth_handler.compute_auth_events(
                event, prev_state_ids, for_verification=False
            )
            auth_events_dict = await self.store.get_events(auth_events_ids)
            # Some needed auth events might be in the batch, combine them with those
            # fetched from the database.
            for auth_event_id in auth_events_ids:
                auth_event = event_id_to_event.get(auth_event_id)
                if auth_event:
                    auth_events_dict[auth_event_id] = auth_event
            auth_events = {(e.type, e.state_key): e for e in auth_events_dict.values()}

        sender_level = get_user_power_level(event.sender, auth_events)

        pl_event = auth_events.get(POWER_KEY)

        return pl_event.content if pl_event else {}, sender_level

    async def _related_events(
        self, event: EventBase
    ) -> Dict[str, Dict[str, JsonValue]]:
        """Fetches the related events for 'event'. Sets the im.vector.is_falling_back key if the event is from a fallback relation

        Returns:
            Mapping of relation type to flattened events.
        """
        related_events: Dict[str, Dict[str, JsonValue]] = {}
        if self._related_event_match_enabled:
            related_event_id = event.content.get("m.relates_to", {}).get("event_id")
            relation_type = event.content.get("m.relates_to", {}).get("rel_type")
            if related_event_id is not None and relation_type is not None:
                related_event = await self.store.get_event(
                    related_event_id, allow_none=True
                )
                if related_event is not None:
                    related_events[relation_type] = _flatten_dict(related_event)

            reply_event_id = (
                event.content.get("m.relates_to", {})
                .get("m.in_reply_to", {})
                .get("event_id")
            )

            # convert replies to pseudo relations
            if reply_event_id is not None:
                related_event = await self.store.get_event(
                    reply_event_id, allow_none=True
                )

                if related_event is not None:
                    related_events["m.in_reply_to"] = _flatten_dict(related_event)

                    # indicate that this is from a fallback relation.
                    if relation_type == "m.thread" and event.content.get(
                        "m.relates_to", {}
                    ).get("is_falling_back", False):
                        related_events["m.in_reply_to"][
                            "im.vector.is_falling_back"
                        ] = ""

        return related_events

    async def action_for_events_by_user(
        self, events_and_context: List[Tuple[EventBase, EventContext]]
    ) -> None:
        """Given a list of events and their associated contexts, evaluate the push rules
        for each event, check if the message should increment the unread count, and
        insert the results into the event_push_actions_staging table.
        """
        if not self.should_calculate_push_rules:
            return
        # For batched events the power level events may not have been persisted yet,
        # so we pass in the batched events. Thus if the event cannot be found in the
        # database we can check in the batch.
        event_id_to_event = {e.event_id: e for e, _ in events_and_context}
        for event, context in events_and_context:
            await self._action_for_event_by_user(event, context, event_id_to_event)

    @measure_func("action_for_event_by_user")
    async def _action_for_event_by_user(
        self,
        event: EventBase,
        context: EventContext,
        event_id_to_event: Mapping[str, EventBase],
    ) -> None:
        if (
            not event.internal_metadata.is_notifiable()
            or event.room_id in self.hs.config.server.rooms_to_exclude_from_sync
        ):
            # Push rules for events that aren't notifiable can't be processed by this and
            # we want to skip push notification actions for historical messages
            # because we don't want to notify people about old history back in time.
            # The historical messages also do not have the proper `context.current_state_ids`
            # and `state_groups` because they have `prev_events` that aren't persisted yet
            # (historical messages persisted in reverse-chronological order).
            return

        # Disable counting as unread unless the experimental configuration is
        # enabled, as it can cause additional (unwanted) rows to be added to the
        # event_push_actions table.
        count_as_unread = False
        if self.hs.config.experimental.msc2654_enabled:
            count_as_unread = _should_count_as_unread(event, context)

        rules_by_user = await self._get_rules_for_event(event)
        actions_by_user: Dict[str, Collection[Union[Mapping, str]]] = {}

        # Gather a bunch of info in parallel.
        #
        # This has a lot of ignored types and casting due to the use of @cached
        # decorated functions passed into run_in_background.
        #
        # See https://github.com/matrix-org/synapse/issues/16606
        (
            room_member_count,
            (power_levels, sender_power_level),
            related_events,
            profiles,
        ) = await make_deferred_yieldable(
            cast(
                "Deferred[Tuple[int, Tuple[dict, Optional[int]], Dict[str, Dict[str, JsonValue]], Mapping[str, ProfileInfo]]]",
                gather_results(
                    (
                        run_in_background(  # type: ignore[call-arg]
                            self.store.get_number_joined_users_in_room, event.room_id  # type: ignore[arg-type]
                        ),
                        run_in_background(
                            self._get_power_levels_and_sender_level,
                            event,
                            context,
                            event_id_to_event,
                        ),
                        run_in_background(self._related_events, event),
                        run_in_background(  # type: ignore[call-arg]
                            self.store.get_subset_users_in_room_with_profiles,
                            event.room_id,  # type: ignore[arg-type]
                            rules_by_user.keys(),  # type: ignore[arg-type]
                        ),
                    ),
                    consumeErrors=True,
                ).addErrback(unwrapFirstError),
            )
        )

        # Find the event's thread ID.
        relation = relation_from_event(event)
        # If the event does not have a relation, then it cannot have a thread ID.
        thread_id = MAIN_TIMELINE
        if relation:
            # Recursively attempt to find the thread this event relates to.
            if relation.rel_type == RelationTypes.THREAD:
                thread_id = relation.parent_id
            else:
                # Since the event has not yet been persisted we check whether
                # the parent is part of a thread.
                thread_id = await self.store.get_thread_id(relation.parent_id)

        # It's possible that old room versions have non-integer power levels (floats or
        # strings; even the occasional `null`). For old rooms, we interpret these as if
        # they were integers. Do this here for the `@room` power level threshold.
        # Note that this is done automatically for the sender's power level by
        # _get_power_levels_and_sender_level in its call to get_user_power_level
        # (even for room V10.)
        notification_levels = power_levels.get("notifications", {})
        if not event.room_version.enforce_int_power_levels:
            keys = list(notification_levels.keys())
            for key in keys:
                level = notification_levels.get(key, SENTINEL)
                if level is not SENTINEL and type(level) is not int:  # noqa: E721
                    try:
                        notification_levels[key] = int(level)
                    except (TypeError, ValueError):
                        del notification_levels[key]

        # Pull out any user and room mentions.
        has_mentions = EventContentFields.MENTIONS in event.content

        evaluator = PushRuleEvaluator(
            _flatten_dict(event),
            has_mentions,
            room_member_count,
            sender_power_level,
            notification_levels,
            related_events,
            self._related_event_match_enabled,
            event.room_version.msc3931_push_features,
            self.hs.config.experimental.msc1767_enabled,  # MSC3931 flag
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


def _is_simple_value(value: Any) -> bool:
    return (
        isinstance(value, (bool, str))
        or type(value) is int  # noqa: E721
        or value is None
    )


def _flatten_dict(
    d: Union[EventBase, Mapping[str, Any]],
    prefix: Optional[List[str]] = None,
    result: Optional[Dict[str, JsonValue]] = None,
) -> Dict[str, JsonValue]:
    """
    Given a JSON dictionary (or event) which might contain sub dictionaries,
    flatten it into a single layer dictionary by combining the keys & sub-keys.

    String, integer, boolean, null or lists of those values are kept. All others are dropped.

    Transforms:

        {"foo": {"bar": "test"}}

    To:

        {"foo.bar": "test"}

    Args:
        d: The event or content to continue flattening.
        prefix: The key prefix (from outer dictionaries).
        result: The result to mutate.

    Returns:
        The resulting dictionary.
    """
    if prefix is None:
        prefix = []
    if result is None:
        result = {}
    for key, value in d.items():
        # Escape periods in the key with a backslash (and backslashes with an
        # extra backslash). This is since a period is used as a separator between
        # nested fields.
        key = key.replace("\\", "\\\\").replace(".", "\\.")

        if _is_simple_value(value):
            result[".".join(prefix + [key])] = value
        elif isinstance(value, (list, tuple)):
            result[".".join(prefix + [key])] = [v for v in value if _is_simple_value(v)]
        elif isinstance(value, Mapping):
            # do not set `room_version` due to recursion considerations below
            _flatten_dict(value, prefix=(prefix + [key]), result=result)

    # `room_version` should only ever be set when looking at the top level of an event
    if (
        isinstance(d, EventBase)
        and PushRuleRoomFlag.EXTENSIBLE_EVENTS in d.room_version.msc3931_push_features
    ):
        # Room supports extensible events: replace `content.body` with the plain text
        # representation from `m.markup`, as per MSC1767.
        markup = d.get("content").get("m.markup")
        if d.room_version.identifier.startswith("org.matrix.msc1767."):
            markup = d.get("content").get("org.matrix.msc1767.markup")
        if markup is not None and isinstance(markup, list):
            text = ""
            for rep in markup:
                if not isinstance(rep, dict):
                    # invalid markup - skip all processing
                    break
                if rep.get("mimetype", "text/plain") == "text/plain":
                    rep_text = rep.get("body")
                    if rep_text is not None and isinstance(rep_text, str):
                        text = rep_text.lower()
                        break
            result["content.body"] = text

    return result
