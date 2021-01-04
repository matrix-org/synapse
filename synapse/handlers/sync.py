# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018, 2019 New Vector Ltd
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
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional, Set, Tuple

import attr
from prometheus_client import Counter

from synapse.api.constants import AccountDataTypes, EventTypes, Membership
from synapse.api.filtering import FilterCollection
from synapse.events import EventBase
from synapse.logging.context import current_context
from synapse.push.clientformat import format_push_rules_for_user
from synapse.storage.roommember import MemberSummary
from synapse.storage.state import StateFilter
from synapse.types import (
    Collection,
    JsonDict,
    MutableStateMap,
    Requester,
    RoomStreamToken,
    StateMap,
    StreamToken,
    UserID,
)
from synapse.util.async_helpers import concurrently_execute
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.response_cache import ResponseCache
from synapse.util.metrics import Measure, measure_func
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# Debug logger for https://github.com/matrix-org/synapse/issues/4422
issue4422_logger = logging.getLogger("synapse.handler.sync.4422_debug")


# Counts the number of times we returned a non-empty sync. `type` is one of
# "initial_sync", "full_state_sync" or "incremental_sync", `lazy_loaded` is
# "true" or "false" depending on if the request asked for lazy loaded members or
# not.
non_empty_sync_counter = Counter(
    "synapse_handlers_sync_nonempty_total",
    "Count of non empty sync responses. type is initial_sync/full_state_sync"
    "/incremental_sync. lazy_loaded indicates if lazy loaded members were "
    "enabled for that request.",
    ["type", "lazy_loaded"],
)

# Store the cache that tracks which lazy-loaded members have been sent to a given
# client for no more than 30 minutes.
LAZY_LOADED_MEMBERS_CACHE_MAX_AGE = 30 * 60 * 1000

# Remember the last 100 members we sent to a client for the purposes of
# avoiding redundantly sending the same lazy-loaded members to the client
LAZY_LOADED_MEMBERS_CACHE_MAX_SIZE = 100


@attr.s(slots=True, frozen=True)
class SyncConfig:
    user = attr.ib(type=UserID)
    filter_collection = attr.ib(type=FilterCollection)
    is_guest = attr.ib(type=bool)
    request_key = attr.ib(type=Tuple[Any, ...])
    device_id = attr.ib(type=str)


@attr.s(slots=True, frozen=True)
class TimelineBatch:
    prev_batch = attr.ib(type=StreamToken)
    events = attr.ib(type=List[EventBase])
    limited = attr.ib(type=bool)

    def __bool__(self) -> bool:
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(self.events)


# We can't freeze this class, because we need to update it after it's instantiated to
# update its unread count. This is because we calculate the unread count for a room only
# if there are updates for it, which we check after the instance has been created.
# This should not be a big deal because we update the notification counts afterwards as
# well anyway.
@attr.s(slots=True)
class JoinedSyncResult:
    room_id = attr.ib(type=str)
    timeline = attr.ib(type=TimelineBatch)
    state = attr.ib(type=StateMap[EventBase])
    ephemeral = attr.ib(type=List[JsonDict])
    account_data = attr.ib(type=List[JsonDict])
    unread_notifications = attr.ib(type=JsonDict)
    summary = attr.ib(type=Optional[JsonDict])
    unread_count = attr.ib(type=int)

    def __bool__(self) -> bool:
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(
            self.timeline
            or self.state
            or self.ephemeral
            or self.account_data
            # nb the notification count does not, er, count: if there's nothing
            # else in the result, we don't need to send it.
        )


@attr.s(slots=True, frozen=True)
class ArchivedSyncResult:
    room_id = attr.ib(type=str)
    timeline = attr.ib(type=TimelineBatch)
    state = attr.ib(type=StateMap[EventBase])
    account_data = attr.ib(type=List[JsonDict])

    def __bool__(self) -> bool:
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(self.timeline or self.state or self.account_data)


@attr.s(slots=True, frozen=True)
class InvitedSyncResult:
    room_id = attr.ib(type=str)
    invite = attr.ib(type=EventBase)

    def __bool__(self) -> bool:
        """Invited rooms should always be reported to the client"""
        return True


@attr.s(slots=True, frozen=True)
class GroupsSyncResult:
    join = attr.ib(type=JsonDict)
    invite = attr.ib(type=JsonDict)
    leave = attr.ib(type=JsonDict)

    def __bool__(self) -> bool:
        return bool(self.join or self.invite or self.leave)


@attr.s(slots=True, frozen=True)
class DeviceLists:
    """
    Attributes:
        changed: List of user_ids whose devices may have changed
        left: List of user_ids whose devices we no longer track
    """

    changed = attr.ib(type=Collection[str])
    left = attr.ib(type=Collection[str])

    def __bool__(self) -> bool:
        return bool(self.changed or self.left)


@attr.s(slots=True)
class _RoomChanges:
    """The set of room entries to include in the sync, plus the set of joined
    and left room IDs since last sync.
    """

    room_entries = attr.ib(type=List["RoomSyncResultBuilder"])
    invited = attr.ib(type=List[InvitedSyncResult])
    newly_joined_rooms = attr.ib(type=List[str])
    newly_left_rooms = attr.ib(type=List[str])


@attr.s(slots=True, frozen=True)
class SyncResult:
    """
    Attributes:
        next_batch: Token for the next sync
        presence: List of presence events for the user.
        account_data: List of account_data events for the user.
        joined: JoinedSyncResult for each joined room.
        invited: InvitedSyncResult for each invited room.
        archived: ArchivedSyncResult for each archived room.
        to_device: List of direct messages for the device.
        device_lists: List of user_ids whose devices have changed
        device_one_time_keys_count: Dict of algorithm to count for one time keys
            for this device
        device_unused_fallback_key_types: List of key types that have an unused fallback
            key
        groups: Group updates, if any
    """

    next_batch = attr.ib(type=StreamToken)
    presence = attr.ib(type=List[JsonDict])
    account_data = attr.ib(type=List[JsonDict])
    joined = attr.ib(type=List[JoinedSyncResult])
    invited = attr.ib(type=List[InvitedSyncResult])
    archived = attr.ib(type=List[ArchivedSyncResult])
    to_device = attr.ib(type=List[JsonDict])
    device_lists = attr.ib(type=DeviceLists)
    device_one_time_keys_count = attr.ib(type=JsonDict)
    device_unused_fallback_key_types = attr.ib(type=List[str])
    groups = attr.ib(type=Optional[GroupsSyncResult])

    def __bool__(self) -> bool:
        """Make the result appear empty if there are no updates. This is used
        to tell if the notifier needs to wait for more events when polling for
        events.
        """
        return bool(
            self.presence
            or self.joined
            or self.invited
            or self.archived
            or self.account_data
            or self.to_device
            or self.device_lists
            or self.groups
        )


class SyncHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs_config = hs.config
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self.presence_handler = hs.get_presence_handler()
        self.event_sources = hs.get_event_sources()
        self.clock = hs.get_clock()
        self.response_cache = ResponseCache(
            hs, "sync"
        )  # type: ResponseCache[Tuple[Any, ...]]
        self.state = hs.get_state_handler()
        self.auth = hs.get_auth()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state

        # ExpiringCache((User, Device)) -> LruCache(state_key => event_id)
        self.lazy_loaded_members_cache = ExpiringCache(
            "lazy_loaded_members_cache",
            self.clock,
            max_len=0,
            expiry_ms=LAZY_LOADED_MEMBERS_CACHE_MAX_AGE,
        )

    async def wait_for_sync_for_user(
        self,
        requester: Requester,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken] = None,
        timeout: int = 0,
        full_state: bool = False,
    ) -> SyncResult:
        """Get the sync for a client if we have new data for it now. Otherwise
        wait for new data to arrive on the server. If the timeout expires, then
        return an empty sync result.
        """
        # If the user is not part of the mau group, then check that limits have
        # not been exceeded (if not part of the group by this point, almost certain
        # auth_blocking will occur)
        user_id = sync_config.user.to_string()
        await self.auth.check_auth_blocking(requester=requester)

        res = await self.response_cache.wrap(
            sync_config.request_key,
            self._wait_for_sync_for_user,
            sync_config,
            since_token,
            timeout,
            full_state,
        )
        logger.debug("Returning sync response for %s", user_id)
        return res

    async def _wait_for_sync_for_user(
        self,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken] = None,
        timeout: int = 0,
        full_state: bool = False,
    ) -> SyncResult:
        if since_token is None:
            sync_type = "initial_sync"
        elif full_state:
            sync_type = "full_state_sync"
        else:
            sync_type = "incremental_sync"

        context = current_context()
        if context:
            context.tag = sync_type

        if timeout == 0 or since_token is None or full_state:
            # we are going to return immediately, so don't bother calling
            # notifier.wait_for_events.
            result = await self.current_sync_for_user(
                sync_config, since_token, full_state=full_state
            )
        else:

            def current_sync_callback(before_token, after_token):
                return self.current_sync_for_user(sync_config, since_token)

            result = await self.notifier.wait_for_events(
                sync_config.user.to_string(),
                timeout,
                current_sync_callback,
                from_token=since_token,
            )

        if result:
            if sync_config.filter_collection.lazy_load_members():
                lazy_loaded = "true"
            else:
                lazy_loaded = "false"
            non_empty_sync_counter.labels(sync_type, lazy_loaded).inc()

        return result

    async def current_sync_for_user(
        self,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken] = None,
        full_state: bool = False,
    ) -> SyncResult:
        """Get the sync for client needed to match what the server has now.
        """
        return await self.generate_sync_result(sync_config, since_token, full_state)

    async def push_rules_for_user(self, user: UserID) -> JsonDict:
        user_id = user.to_string()
        rules = await self.store.get_push_rules_for_user(user_id)
        rules = format_push_rules_for_user(user, rules)
        return rules

    async def ephemeral_by_room(
        self,
        sync_result_builder: "SyncResultBuilder",
        now_token: StreamToken,
        since_token: Optional[StreamToken] = None,
    ) -> Tuple[StreamToken, Dict[str, List[JsonDict]]]:
        """Get the ephemeral events for each room the user is in
        Args:
            sync_result_builder
            now_token: Where the server is currently up to.
            since_token: Where the server was when the client
                last synced.
        Returns:
            A tuple of the now StreamToken, updated to reflect the which typing
            events are included, and a dict mapping from room_id to a list of
            typing events for that room.
        """

        sync_config = sync_result_builder.sync_config

        with Measure(self.clock, "ephemeral_by_room"):
            typing_key = since_token.typing_key if since_token else 0

            room_ids = sync_result_builder.joined_room_ids

            typing_source = self.event_sources.sources["typing"]
            typing, typing_key = await typing_source.get_new_events(
                user=sync_config.user,
                from_key=typing_key,
                limit=sync_config.filter_collection.ephemeral_limit(),
                room_ids=room_ids,
                is_guest=sync_config.is_guest,
            )
            now_token = now_token.copy_and_replace("typing_key", typing_key)

            ephemeral_by_room = {}  # type: JsonDict

            for event in typing:
                # we want to exclude the room_id from the event, but modifying the
                # result returned by the event source is poor form (it might cache
                # the object)
                room_id = event["room_id"]
                event_copy = {k: v for (k, v) in event.items() if k != "room_id"}
                ephemeral_by_room.setdefault(room_id, []).append(event_copy)

            receipt_key = since_token.receipt_key if since_token else 0

            receipt_source = self.event_sources.sources["receipt"]
            receipts, receipt_key = await receipt_source.get_new_events(
                user=sync_config.user,
                from_key=receipt_key,
                limit=sync_config.filter_collection.ephemeral_limit(),
                room_ids=room_ids,
                is_guest=sync_config.is_guest,
            )
            now_token = now_token.copy_and_replace("receipt_key", receipt_key)

            for event in receipts:
                room_id = event["room_id"]
                # exclude room id, as above
                event_copy = {k: v for (k, v) in event.items() if k != "room_id"}
                ephemeral_by_room.setdefault(room_id, []).append(event_copy)

        return now_token, ephemeral_by_room

    async def _load_filtered_recents(
        self,
        room_id: str,
        sync_config: SyncConfig,
        now_token: StreamToken,
        since_token: Optional[StreamToken] = None,
        potential_recents: Optional[List[EventBase]] = None,
        newly_joined_room: bool = False,
    ) -> TimelineBatch:
        with Measure(self.clock, "load_filtered_recents"):
            timeline_limit = sync_config.filter_collection.timeline_limit()
            block_all_timeline = (
                sync_config.filter_collection.blocks_all_room_timeline()
            )

            if (
                potential_recents is None
                or newly_joined_room
                or timeline_limit < len(potential_recents)
            ):
                limited = True
            else:
                limited = False

            if potential_recents:
                recents = sync_config.filter_collection.filter_room_timeline(
                    potential_recents
                )

                # We check if there are any state events, if there are then we pass
                # all current state events to the filter_events function. This is to
                # ensure that we always include current state in the timeline
                current_state_ids = frozenset()  # type: FrozenSet[str]
                if any(e.is_state() for e in recents):
                    current_state_ids_map = await self.state.get_current_state_ids(
                        room_id
                    )
                    current_state_ids = frozenset(current_state_ids_map.values())

                recents = await filter_events_for_client(
                    self.storage,
                    sync_config.user.to_string(),
                    recents,
                    always_include_ids=current_state_ids,
                )
            else:
                recents = []

            if not limited or block_all_timeline:
                prev_batch_token = now_token
                if recents:
                    room_key = recents[0].internal_metadata.before
                    prev_batch_token = now_token.copy_and_replace("room_key", room_key)

                return TimelineBatch(
                    events=recents, prev_batch=prev_batch_token, limited=False
                )

            filtering_factor = 2
            load_limit = max(timeline_limit * filtering_factor, 10)
            max_repeat = 5  # Only try a few times per room, otherwise
            room_key = now_token.room_key
            end_key = room_key

            since_key = None
            if since_token and not newly_joined_room:
                since_key = since_token.room_key

            while limited and len(recents) < timeline_limit and max_repeat:
                # If we have a since_key then we are trying to get any events
                # that have happened since `since_key` up to `end_key`, so we
                # can just use `get_room_events_stream_for_room`.
                # Otherwise, we want to return the last N events in the room
                # in toplogical ordering.
                if since_key:
                    events, end_key = await self.store.get_room_events_stream_for_room(
                        room_id,
                        limit=load_limit + 1,
                        from_key=since_key,
                        to_key=end_key,
                    )
                else:
                    events, end_key = await self.store.get_recent_events_for_room(
                        room_id, limit=load_limit + 1, end_token=end_key
                    )
                loaded_recents = sync_config.filter_collection.filter_room_timeline(
                    events
                )

                # We check if there are any state events, if there are then we pass
                # all current state events to the filter_events function. This is to
                # ensure that we always include current state in the timeline
                current_state_ids = frozenset()
                if any(e.is_state() for e in loaded_recents):
                    current_state_ids_map = await self.state.get_current_state_ids(
                        room_id
                    )
                    current_state_ids = frozenset(current_state_ids_map.values())

                loaded_recents = await filter_events_for_client(
                    self.storage,
                    sync_config.user.to_string(),
                    loaded_recents,
                    always_include_ids=current_state_ids,
                )
                loaded_recents.extend(recents)
                recents = loaded_recents

                if len(events) <= load_limit:
                    limited = False
                    break
                max_repeat -= 1

            if len(recents) > timeline_limit:
                limited = True
                recents = recents[-timeline_limit:]
                room_key = recents[0].internal_metadata.before

            prev_batch_token = now_token.copy_and_replace("room_key", room_key)

        return TimelineBatch(
            events=recents,
            prev_batch=prev_batch_token,
            limited=limited or newly_joined_room,
        )

    async def get_state_after_event(
        self, event: EventBase, state_filter: StateFilter = StateFilter.all()
    ) -> StateMap[str]:
        """
        Get the room state after the given event

        Args:
            event: event of interest
            state_filter: The state filter used to fetch state from the database.
        """
        state_ids = await self.state_store.get_state_ids_for_event(
            event.event_id, state_filter=state_filter
        )
        if event.is_state():
            state_ids = dict(state_ids)
            state_ids[(event.type, event.state_key)] = event.event_id
        return state_ids

    async def get_state_at(
        self,
        room_id: str,
        stream_position: StreamToken,
        state_filter: StateFilter = StateFilter.all(),
    ) -> StateMap[str]:
        """ Get the room state at a particular stream position

        Args:
            room_id: room for which to get state
            stream_position: point at which to get state
            state_filter: The state filter used to fetch state from the database.
        """
        # FIXME this claims to get the state at a stream position, but
        # get_recent_events_for_room operates by topo ordering. This therefore
        # does not reliably give you the state at the given stream position.
        # (https://github.com/matrix-org/synapse/issues/3305)
        last_events, _ = await self.store.get_recent_events_for_room(
            room_id, end_token=stream_position.room_key, limit=1
        )

        if last_events:
            last_event = last_events[-1]
            state = await self.get_state_after_event(
                last_event, state_filter=state_filter
            )

        else:
            # no events in this room - so presumably no state
            state = {}
        return state

    async def compute_summary(
        self,
        room_id: str,
        sync_config: SyncConfig,
        batch: TimelineBatch,
        state: MutableStateMap[EventBase],
        now_token: StreamToken,
    ) -> Optional[JsonDict]:
        """ Works out a room summary block for this room, summarising the number
        of joined members in the room, and providing the 'hero' members if the
        room has no name so clients can consistently name rooms.  Also adds
        state events to 'state' if needed to describe the heroes.

        Args
            room_id
            sync_config
            batch: The timeline batch for the room that will be sent to the user.
            state: State as returned by compute_state_delta
            now_token: Token of the end of the current batch.
        """

        # FIXME: we could/should get this from room_stats when matthew/stats lands

        # FIXME: this promulgates https://github.com/matrix-org/synapse/issues/3305
        last_events, _ = await self.store.get_recent_event_ids_for_room(
            room_id, end_token=now_token.room_key, limit=1
        )

        if not last_events:
            return None

        last_event = last_events[-1]
        state_ids = await self.state_store.get_state_ids_for_event(
            last_event.event_id,
            state_filter=StateFilter.from_types(
                [(EventTypes.Name, ""), (EventTypes.CanonicalAlias, "")]
            ),
        )

        # this is heavily cached, thus: fast.
        details = await self.store.get_room_summary(room_id)

        name_id = state_ids.get((EventTypes.Name, ""))
        canonical_alias_id = state_ids.get((EventTypes.CanonicalAlias, ""))

        summary = {}
        empty_ms = MemberSummary([], 0)

        # TODO: only send these when they change.
        summary["m.joined_member_count"] = details.get(Membership.JOIN, empty_ms).count
        summary["m.invited_member_count"] = details.get(
            Membership.INVITE, empty_ms
        ).count

        # if the room has a name or canonical_alias set, we can skip
        # calculating heroes. Empty strings are falsey, so we check
        # for the "name" value and default to an empty string.
        if name_id:
            name = await self.store.get_event(name_id, allow_none=True)
            if name and name.content.get("name"):
                return summary

        if canonical_alias_id:
            canonical_alias = await self.store.get_event(
                canonical_alias_id, allow_none=True
            )
            if canonical_alias and canonical_alias.content.get("alias"):
                return summary

        me = sync_config.user.to_string()

        joined_user_ids = [
            r[0] for r in details.get(Membership.JOIN, empty_ms).members if r[0] != me
        ]
        invited_user_ids = [
            r[0] for r in details.get(Membership.INVITE, empty_ms).members if r[0] != me
        ]
        gone_user_ids = [
            r[0] for r in details.get(Membership.LEAVE, empty_ms).members if r[0] != me
        ] + [r[0] for r in details.get(Membership.BAN, empty_ms).members if r[0] != me]

        # FIXME: only build up a member_ids list for our heroes
        member_ids = {}
        for membership in (
            Membership.JOIN,
            Membership.INVITE,
            Membership.LEAVE,
            Membership.BAN,
        ):
            for user_id, event_id in details.get(membership, empty_ms).members:
                member_ids[user_id] = event_id

        # FIXME: order by stream ordering rather than as returned by SQL
        if joined_user_ids or invited_user_ids:
            summary["m.heroes"] = sorted(joined_user_ids + invited_user_ids)[0:5]
        else:
            summary["m.heroes"] = sorted(gone_user_ids)[0:5]

        if not sync_config.filter_collection.lazy_load_members():
            return summary

        # ensure we send membership events for heroes if needed
        cache_key = (sync_config.user.to_string(), sync_config.device_id)
        cache = self.get_lazy_loaded_members_cache(cache_key)

        # track which members the client should already know about via LL:
        # Ones which are already in state...
        existing_members = {
            user_id for (typ, user_id) in state.keys() if typ == EventTypes.Member
        }

        # ...or ones which are in the timeline...
        for ev in batch.events:
            if ev.type == EventTypes.Member:
                existing_members.add(ev.state_key)

        # ...and then ensure any missing ones get included in state.
        missing_hero_event_ids = [
            member_ids[hero_id]
            for hero_id in summary["m.heroes"]
            if (
                cache.get(hero_id) != member_ids[hero_id]
                and hero_id not in existing_members
            )
        ]

        missing_hero_state = await self.store.get_events(missing_hero_event_ids)

        for s in missing_hero_state.values():
            cache.set(s.state_key, s.event_id)
            state[(EventTypes.Member, s.state_key)] = s

        return summary

    def get_lazy_loaded_members_cache(self, cache_key: Tuple[str, str]) -> LruCache:
        cache = self.lazy_loaded_members_cache.get(cache_key)
        if cache is None:
            logger.debug("creating LruCache for %r", cache_key)
            cache = LruCache(LAZY_LOADED_MEMBERS_CACHE_MAX_SIZE)
            self.lazy_loaded_members_cache[cache_key] = cache
        else:
            logger.debug("found LruCache for %r", cache_key)
        return cache

    async def compute_state_delta(
        self,
        room_id: str,
        batch: TimelineBatch,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken],
        now_token: StreamToken,
        full_state: bool,
    ) -> MutableStateMap[EventBase]:
        """ Works out the difference in state between the start of the timeline
        and the previous sync.

        Args:
            room_id:
            batch: The timeline batch for the room that will be sent to the user.
            sync_config:
            since_token: Token of the end of the previous batch. May be None.
            now_token: Token of the end of the current batch.
            full_state: Whether to force returning the full state.
        """
        # TODO(mjark) Check if the state events were received by the server
        # after the previous sync, since we need to include those state
        # updates even if they occurred logically before the previous event.
        # TODO(mjark) Check for new redactions in the state events.

        with Measure(self.clock, "compute_state_delta"):

            members_to_fetch = None

            lazy_load_members = sync_config.filter_collection.lazy_load_members()
            include_redundant_members = (
                sync_config.filter_collection.include_redundant_members()
            )

            if lazy_load_members:
                # We only request state for the members needed to display the
                # timeline:

                members_to_fetch = {
                    event.sender  # FIXME: we also care about invite targets etc.
                    for event in batch.events
                }

                if full_state:
                    # always make sure we LL ourselves so we know we're in the room
                    # (if we are) to fix https://github.com/vector-im/riot-web/issues/7209
                    # We only need apply this on full state syncs given we disabled
                    # LL for incr syncs in #3840.
                    members_to_fetch.add(sync_config.user.to_string())

                state_filter = StateFilter.from_lazy_load_member_list(members_to_fetch)
            else:
                state_filter = StateFilter.all()

            timeline_state = {
                (event.type, event.state_key): event.event_id
                for event in batch.events
                if event.is_state()
            }

            if full_state:
                if batch:
                    current_state_ids = await self.state_store.get_state_ids_for_event(
                        batch.events[-1].event_id, state_filter=state_filter
                    )

                    state_ids = await self.state_store.get_state_ids_for_event(
                        batch.events[0].event_id, state_filter=state_filter
                    )

                else:
                    current_state_ids = await self.get_state_at(
                        room_id, stream_position=now_token, state_filter=state_filter
                    )

                    state_ids = current_state_ids

                state_ids = _calculate_state(
                    timeline_contains=timeline_state,
                    timeline_start=state_ids,
                    previous={},
                    current=current_state_ids,
                    lazy_load_members=lazy_load_members,
                )
            elif batch.limited:
                if batch:
                    state_at_timeline_start = await self.state_store.get_state_ids_for_event(
                        batch.events[0].event_id, state_filter=state_filter
                    )
                else:
                    # We can get here if the user has ignored the senders of all
                    # the recent events.
                    state_at_timeline_start = await self.get_state_at(
                        room_id, stream_position=now_token, state_filter=state_filter
                    )

                # for now, we disable LL for gappy syncs - see
                # https://github.com/vector-im/riot-web/issues/7211#issuecomment-419976346
                # N.B. this slows down incr syncs as we are now processing way
                # more state in the server than if we were LLing.
                #
                # We still have to filter timeline_start to LL entries (above) in order
                # for _calculate_state's LL logic to work, as we have to include LL
                # members for timeline senders in case they weren't loaded in the initial
                # sync.  We do this by (counterintuitively) by filtering timeline_start
                # members to just be ones which were timeline senders, which then ensures
                # all of the rest get included in the state block (if we need to know
                # about them).
                state_filter = StateFilter.all()

                # If this is an initial sync then full_state should be set, and
                # that case is handled above. We assert here to ensure that this
                # is indeed the case.
                assert since_token is not None
                state_at_previous_sync = await self.get_state_at(
                    room_id, stream_position=since_token, state_filter=state_filter
                )

                if batch:
                    current_state_ids = await self.state_store.get_state_ids_for_event(
                        batch.events[-1].event_id, state_filter=state_filter
                    )
                else:
                    # Its not clear how we get here, but empirically we do
                    # (#5407). Logging has been added elsewhere to try and
                    # figure out where this state comes from.
                    current_state_ids = await self.get_state_at(
                        room_id, stream_position=now_token, state_filter=state_filter
                    )

                state_ids = _calculate_state(
                    timeline_contains=timeline_state,
                    timeline_start=state_at_timeline_start,
                    previous=state_at_previous_sync,
                    current=current_state_ids,
                    # we have to include LL members in case LL initial sync missed them
                    lazy_load_members=lazy_load_members,
                )
            else:
                state_ids = {}
                if lazy_load_members:
                    if members_to_fetch and batch.events:
                        # We're returning an incremental sync, with no
                        # "gap" since the previous sync, so normally there would be
                        # no state to return.
                        # But we're lazy-loading, so the client might need some more
                        # member events to understand the events in this timeline.
                        # So we fish out all the member events corresponding to the
                        # timeline here, and then dedupe any redundant ones below.

                        state_ids = await self.state_store.get_state_ids_for_event(
                            batch.events[0].event_id,
                            # we only want members!
                            state_filter=StateFilter.from_types(
                                (EventTypes.Member, member)
                                for member in members_to_fetch
                            ),
                        )

            if lazy_load_members and not include_redundant_members:
                cache_key = (sync_config.user.to_string(), sync_config.device_id)
                cache = self.get_lazy_loaded_members_cache(cache_key)

                # if it's a new sync sequence, then assume the client has had
                # amnesia and doesn't want any recent lazy-loaded members
                # de-duplicated.
                if since_token is None:
                    logger.debug("clearing LruCache for %r", cache_key)
                    cache.clear()
                else:
                    # only send members which aren't in our LruCache (either
                    # because they're new to this client or have been pushed out
                    # of the cache)
                    logger.debug("filtering state from %r...", state_ids)
                    state_ids = {
                        t: event_id
                        for t, event_id in state_ids.items()
                        if cache.get(t[1]) != event_id
                    }
                    logger.debug("...to %r", state_ids)

                # add any member IDs we are about to send into our LruCache
                for t, event_id in itertools.chain(
                    state_ids.items(), timeline_state.items()
                ):
                    if t[0] == EventTypes.Member:
                        cache.set(t[1], event_id)

        state = {}  # type: Dict[str, EventBase]
        if state_ids:
            state = await self.store.get_events(list(state_ids.values()))

        return {
            (e.type, e.state_key): e
            for e in sync_config.filter_collection.filter_room_state(
                list(state.values())
            )
            if e.type != EventTypes.Aliases  # until MSC2261 or alternative solution
        }

    async def unread_notifs_for_room_id(
        self, room_id: str, sync_config: SyncConfig
    ) -> Dict[str, int]:
        with Measure(self.clock, "unread_notifs_for_room_id"):
            last_unread_event_id = await self.store.get_last_receipt_event_id_for_user(
                user_id=sync_config.user.to_string(),
                room_id=room_id,
                receipt_type="m.read",
            )

            notifs = await self.store.get_unread_event_push_actions_by_room_for_user(
                room_id, sync_config.user.to_string(), last_unread_event_id
            )
            return notifs

    async def generate_sync_result(
        self,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken] = None,
        full_state: bool = False,
    ) -> SyncResult:
        """Generates a sync result.
        """
        # NB: The now_token gets changed by some of the generate_sync_* methods,
        # this is due to some of the underlying streams not supporting the ability
        # to query up to a given point.
        # Always use the `now_token` in `SyncResultBuilder`
        now_token = self.event_sources.get_current_token()

        logger.debug(
            "Calculating sync response for %r between %s and %s",
            sync_config.user,
            since_token,
            now_token,
        )

        user_id = sync_config.user.to_string()
        app_service = self.store.get_app_service_by_user_id(user_id)
        if app_service:
            # We no longer support AS users using /sync directly.
            # See https://github.com/matrix-org/matrix-doc/issues/1144
            raise NotImplementedError()
        else:
            joined_room_ids = await self.get_rooms_for_user_at(
                user_id, now_token.room_key
            )
        sync_result_builder = SyncResultBuilder(
            sync_config,
            full_state,
            since_token=since_token,
            now_token=now_token,
            joined_room_ids=joined_room_ids,
        )

        logger.debug("Fetching account data")

        account_data_by_room = await self._generate_sync_entry_for_account_data(
            sync_result_builder
        )

        logger.debug("Fetching room data")

        res = await self._generate_sync_entry_for_rooms(
            sync_result_builder, account_data_by_room
        )
        newly_joined_rooms, newly_joined_or_invited_users, _, _ = res
        _, _, newly_left_rooms, newly_left_users = res

        block_all_presence_data = (
            since_token is None and sync_config.filter_collection.blocks_all_presence()
        )
        if self.hs_config.use_presence and not block_all_presence_data:
            logger.debug("Fetching presence data")
            await self._generate_sync_entry_for_presence(
                sync_result_builder, newly_joined_rooms, newly_joined_or_invited_users
            )

        logger.debug("Fetching to-device data")
        await self._generate_sync_entry_for_to_device(sync_result_builder)

        device_lists = await self._generate_sync_entry_for_device_list(
            sync_result_builder,
            newly_joined_rooms=newly_joined_rooms,
            newly_joined_or_invited_users=newly_joined_or_invited_users,
            newly_left_rooms=newly_left_rooms,
            newly_left_users=newly_left_users,
        )

        logger.debug("Fetching OTK data")
        device_id = sync_config.device_id
        one_time_key_counts = {}  # type: JsonDict
        unused_fallback_key_types = []  # type: List[str]
        if device_id:
            one_time_key_counts = await self.store.count_e2e_one_time_keys(
                user_id, device_id
            )
            unused_fallback_key_types = await self.store.get_e2e_unused_fallback_key_types(
                user_id, device_id
            )

        logger.debug("Fetching group data")
        await self._generate_sync_entry_for_groups(sync_result_builder)

        # debug for https://github.com/matrix-org/synapse/issues/4422
        for joined_room in sync_result_builder.joined:
            room_id = joined_room.room_id
            if room_id in newly_joined_rooms:
                issue4422_logger.debug(
                    "Sync result for newly joined room %s: %r", room_id, joined_room
                )

        logger.debug("Sync response calculation complete")
        return SyncResult(
            presence=sync_result_builder.presence,
            account_data=sync_result_builder.account_data,
            joined=sync_result_builder.joined,
            invited=sync_result_builder.invited,
            archived=sync_result_builder.archived,
            to_device=sync_result_builder.to_device,
            device_lists=device_lists,
            groups=sync_result_builder.groups,
            device_one_time_keys_count=one_time_key_counts,
            device_unused_fallback_key_types=unused_fallback_key_types,
            next_batch=sync_result_builder.now_token,
        )

    @measure_func("_generate_sync_entry_for_groups")
    async def _generate_sync_entry_for_groups(
        self, sync_result_builder: "SyncResultBuilder"
    ) -> None:
        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token
        now_token = sync_result_builder.now_token

        if since_token and since_token.groups_key:
            results = await self.store.get_groups_changes_for_user(
                user_id, since_token.groups_key, now_token.groups_key
            )
        else:
            results = await self.store.get_all_groups_for_user(
                user_id, now_token.groups_key
            )

        invited = {}
        joined = {}
        left = {}
        for result in results:
            membership = result["membership"]
            group_id = result["group_id"]
            gtype = result["type"]
            content = result["content"]

            if membership == "join":
                if gtype == "membership":
                    # TODO: Add profile
                    content.pop("membership", None)
                    joined[group_id] = content["content"]
                else:
                    joined.setdefault(group_id, {})[gtype] = content
            elif membership == "invite":
                if gtype == "membership":
                    content.pop("membership", None)
                    invited[group_id] = content["content"]
            else:
                if gtype == "membership":
                    left[group_id] = content["content"]

        sync_result_builder.groups = GroupsSyncResult(
            join=joined, invite=invited, leave=left
        )

    @measure_func("_generate_sync_entry_for_device_list")
    async def _generate_sync_entry_for_device_list(
        self,
        sync_result_builder: "SyncResultBuilder",
        newly_joined_rooms: Set[str],
        newly_joined_or_invited_users: Set[str],
        newly_left_rooms: Set[str],
        newly_left_users: Set[str],
    ) -> DeviceLists:
        """Generate the DeviceLists section of sync

        Args:
            sync_result_builder
            newly_joined_rooms: Set of rooms user has joined since previous sync
            newly_joined_or_invited_users: Set of users that have joined or
                been invited to a room since previous sync.
            newly_left_rooms: Set of rooms user has left since previous sync
            newly_left_users: Set of users that have left a room we're in since
                previous sync
        """

        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token

        # We're going to mutate these fields, so lets copy them rather than
        # assume they won't get used later.
        newly_joined_or_invited_users = set(newly_joined_or_invited_users)
        newly_left_users = set(newly_left_users)

        if since_token and since_token.device_list_key:
            # We want to figure out what user IDs the client should refetch
            # device keys for, and which users we aren't going to track changes
            # for anymore.
            #
            # For the first step we check:
            #   a. if any users we share a room with have updated their devices,
            #      and
            #   b. we also check if we've joined any new rooms, or if a user has
            #      joined a room we're in.
            #
            # For the second step we just find any users we no longer share a
            # room with by looking at all users that have left a room plus users
            # that were in a room we've left.

            users_who_share_room = await self.store.get_users_who_share_room_with_user(
                user_id
            )

            # Always tell the user about their own devices. We check as the user
            # ID is almost certainly already included (unless they're not in any
            # rooms) and taking a copy of the set is relatively expensive.
            if user_id not in users_who_share_room:
                users_who_share_room = set(users_who_share_room)
                users_who_share_room.add(user_id)

            tracked_users = users_who_share_room

            # Step 1a, check for changes in devices of users we share a room with
            users_that_have_changed = await self.store.get_users_whose_devices_changed(
                since_token.device_list_key, tracked_users
            )

            # Step 1b, check for newly joined rooms
            for room_id in newly_joined_rooms:
                joined_users = await self.state.get_current_users_in_room(room_id)
                newly_joined_or_invited_users.update(joined_users)

            # TODO: Check that these users are actually new, i.e. either they
            # weren't in the previous sync *or* they left and rejoined.
            users_that_have_changed.update(newly_joined_or_invited_users)

            user_signatures_changed = await self.store.get_users_whose_signatures_changed(
                user_id, since_token.device_list_key
            )
            users_that_have_changed.update(user_signatures_changed)

            # Now find users that we no longer track
            for room_id in newly_left_rooms:
                left_users = await self.state.get_current_users_in_room(room_id)
                newly_left_users.update(left_users)

            # Remove any users that we still share a room with.
            newly_left_users -= users_who_share_room

            return DeviceLists(changed=users_that_have_changed, left=newly_left_users)
        else:
            return DeviceLists(changed=[], left=[])

    async def _generate_sync_entry_for_to_device(
        self, sync_result_builder: "SyncResultBuilder"
    ) -> None:
        """Generates the portion of the sync response. Populates
        `sync_result_builder` with the result.
        """
        user_id = sync_result_builder.sync_config.user.to_string()
        device_id = sync_result_builder.sync_config.device_id
        now_token = sync_result_builder.now_token
        since_stream_id = 0
        if sync_result_builder.since_token is not None:
            since_stream_id = int(sync_result_builder.since_token.to_device_key)

        if since_stream_id != int(now_token.to_device_key):
            # We only delete messages when a new message comes in, but that's
            # fine so long as we delete them at some point.

            deleted = await self.store.delete_messages_for_device(
                user_id, device_id, since_stream_id
            )
            logger.debug(
                "Deleted %d to-device messages up to %d", deleted, since_stream_id
            )

            messages, stream_id = await self.store.get_new_messages_for_device(
                user_id, device_id, since_stream_id, now_token.to_device_key
            )

            logger.debug(
                "Returning %d to-device messages between %d and %d (current token: %d)",
                len(messages),
                since_stream_id,
                stream_id,
                now_token.to_device_key,
            )
            sync_result_builder.now_token = now_token.copy_and_replace(
                "to_device_key", stream_id
            )
            sync_result_builder.to_device = messages
        else:
            sync_result_builder.to_device = []

    async def _generate_sync_entry_for_account_data(
        self, sync_result_builder: "SyncResultBuilder"
    ) -> Dict[str, Dict[str, JsonDict]]:
        """Generates the account data portion of the sync response. Populates
        `sync_result_builder` with the result.

        Args:
            sync_result_builder

        Returns:
            A dictionary containing the per room account data.
        """
        sync_config = sync_result_builder.sync_config
        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token

        if since_token and not sync_result_builder.full_state:
            (
                account_data,
                account_data_by_room,
            ) = await self.store.get_updated_account_data_for_user(
                user_id, since_token.account_data_key
            )

            push_rules_changed = await self.store.have_push_rules_changed_for_user(
                user_id, int(since_token.push_rules_key)
            )

            if push_rules_changed:
                account_data["m.push_rules"] = await self.push_rules_for_user(
                    sync_config.user
                )
        else:
            (
                account_data,
                account_data_by_room,
            ) = await self.store.get_account_data_for_user(sync_config.user.to_string())

            account_data["m.push_rules"] = await self.push_rules_for_user(
                sync_config.user
            )

        account_data_for_user = sync_config.filter_collection.filter_account_data(
            [
                {"type": account_data_type, "content": content}
                for account_data_type, content in account_data.items()
            ]
        )

        sync_result_builder.account_data = account_data_for_user

        return account_data_by_room

    async def _generate_sync_entry_for_presence(
        self,
        sync_result_builder: "SyncResultBuilder",
        newly_joined_rooms: Set[str],
        newly_joined_or_invited_users: Set[str],
    ) -> None:
        """Generates the presence portion of the sync response. Populates the
        `sync_result_builder` with the result.

        Args:
            sync_result_builder
            newly_joined_rooms: Set of rooms that the user has joined since
                the last sync (or empty if an initial sync)
            newly_joined_or_invited_users: Set of users that have joined or
                been invited to rooms since the last sync (or empty if an
                initial sync)
        """
        now_token = sync_result_builder.now_token
        sync_config = sync_result_builder.sync_config
        user = sync_result_builder.sync_config.user

        presence_source = self.event_sources.sources["presence"]

        since_token = sync_result_builder.since_token
        presence_key = None
        include_offline = False
        if since_token and not sync_result_builder.full_state:
            presence_key = since_token.presence_key
            include_offline = True

        presence, presence_key = await presence_source.get_new_events(
            user=user,
            from_key=presence_key,
            is_guest=sync_config.is_guest,
            include_offline=include_offline,
        )
        assert presence_key
        sync_result_builder.now_token = now_token.copy_and_replace(
            "presence_key", presence_key
        )

        extra_users_ids = set(newly_joined_or_invited_users)
        for room_id in newly_joined_rooms:
            users = await self.state.get_current_users_in_room(room_id)
            extra_users_ids.update(users)
        extra_users_ids.discard(user.to_string())

        if extra_users_ids:
            states = await self.presence_handler.get_states(extra_users_ids)
            presence.extend(states)

            # Deduplicate the presence entries so that there's at most one per user
            presence = list({p.user_id: p for p in presence}.values())

        presence = sync_config.filter_collection.filter_presence(presence)

        sync_result_builder.presence = presence

    async def _generate_sync_entry_for_rooms(
        self,
        sync_result_builder: "SyncResultBuilder",
        account_data_by_room: Dict[str, Dict[str, JsonDict]],
    ) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """Generates the rooms portion of the sync response. Populates the
        `sync_result_builder` with the result.

        Args:
            sync_result_builder
            account_data_by_room: Dictionary of per room account data

        Returns:
            Returns a 4-tuple of
            `(newly_joined_rooms, newly_joined_or_invited_users,
            newly_left_rooms, newly_left_users)`
        """
        user_id = sync_result_builder.sync_config.user.to_string()
        block_all_room_ephemeral = (
            sync_result_builder.since_token is None
            and sync_result_builder.sync_config.filter_collection.blocks_all_room_ephemeral()
        )

        if block_all_room_ephemeral:
            ephemeral_by_room = {}  # type: Dict[str, List[JsonDict]]
        else:
            now_token, ephemeral_by_room = await self.ephemeral_by_room(
                sync_result_builder,
                now_token=sync_result_builder.now_token,
                since_token=sync_result_builder.since_token,
            )
            sync_result_builder.now_token = now_token

        # We check up front if anything has changed, if it hasn't then there is
        # no point in going further.
        since_token = sync_result_builder.since_token
        if not sync_result_builder.full_state:
            if since_token and not ephemeral_by_room and not account_data_by_room:
                have_changed = await self._have_rooms_changed(sync_result_builder)
                if not have_changed:
                    tags_by_room = await self.store.get_updated_tags(
                        user_id, since_token.account_data_key
                    )
                    if not tags_by_room:
                        logger.debug("no-oping sync")
                        return set(), set(), set(), set()

        ignored_account_data = await self.store.get_global_account_data_by_type_for_user(
            AccountDataTypes.IGNORED_USER_LIST, user_id=user_id
        )

        # If there is ignored users account data and it matches the proper type,
        # then use it.
        ignored_users = frozenset()  # type: FrozenSet[str]
        if ignored_account_data:
            ignored_users_data = ignored_account_data.get("ignored_users", {})
            if isinstance(ignored_users_data, dict):
                ignored_users = frozenset(ignored_users_data.keys())

        if since_token:
            room_changes = await self._get_rooms_changed(
                sync_result_builder, ignored_users
            )
            tags_by_room = await self.store.get_updated_tags(
                user_id, since_token.account_data_key
            )
        else:
            room_changes = await self._get_all_rooms(sync_result_builder, ignored_users)

            tags_by_room = await self.store.get_tags_for_user(user_id)

        room_entries = room_changes.room_entries
        invited = room_changes.invited
        newly_joined_rooms = room_changes.newly_joined_rooms
        newly_left_rooms = room_changes.newly_left_rooms

        async def handle_room_entries(room_entry):
            logger.debug("Generating room entry for %s", room_entry.room_id)
            res = await self._generate_room_entry(
                sync_result_builder,
                ignored_users,
                room_entry,
                ephemeral=ephemeral_by_room.get(room_entry.room_id, []),
                tags=tags_by_room.get(room_entry.room_id),
                account_data=account_data_by_room.get(room_entry.room_id, {}),
                always_include=sync_result_builder.full_state,
            )
            logger.debug("Generated room entry for %s", room_entry.room_id)
            return res

        await concurrently_execute(handle_room_entries, room_entries, 10)

        sync_result_builder.invited.extend(invited)

        # Now we want to get any newly joined or invited users
        newly_joined_or_invited_users = set()
        newly_left_users = set()
        if since_token:
            for joined_sync in sync_result_builder.joined:
                it = itertools.chain(
                    joined_sync.timeline.events, joined_sync.state.values()
                )
                for event in it:
                    if event.type == EventTypes.Member:
                        if (
                            event.membership == Membership.JOIN
                            or event.membership == Membership.INVITE
                        ):
                            newly_joined_or_invited_users.add(event.state_key)
                        else:
                            prev_content = event.unsigned.get("prev_content", {})
                            prev_membership = prev_content.get("membership", None)
                            if prev_membership == Membership.JOIN:
                                newly_left_users.add(event.state_key)

        newly_left_users -= newly_joined_or_invited_users

        return (
            set(newly_joined_rooms),
            newly_joined_or_invited_users,
            set(newly_left_rooms),
            newly_left_users,
        )

    async def _have_rooms_changed(
        self, sync_result_builder: "SyncResultBuilder"
    ) -> bool:
        """Returns whether there may be any new events that should be sent down
        the sync. Returns True if there are.
        """
        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token
        now_token = sync_result_builder.now_token

        assert since_token

        # Get a list of membership change events that have happened.
        rooms_changed = await self.store.get_membership_changes_for_user(
            user_id, since_token.room_key, now_token.room_key
        )

        if rooms_changed:
            return True

        stream_id = since_token.room_key.stream
        for room_id in sync_result_builder.joined_room_ids:
            if self.store.has_room_changed_since(room_id, stream_id):
                return True
        return False

    async def _get_rooms_changed(
        self, sync_result_builder: "SyncResultBuilder", ignored_users: FrozenSet[str]
    ) -> _RoomChanges:
        """Gets the the changes that have happened since the last sync.
        """
        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token
        now_token = sync_result_builder.now_token
        sync_config = sync_result_builder.sync_config

        assert since_token

        # Get a list of membership change events that have happened.
        rooms_changed = await self.store.get_membership_changes_for_user(
            user_id, since_token.room_key, now_token.room_key
        )

        mem_change_events_by_room_id = {}  # type: Dict[str, List[EventBase]]
        for event in rooms_changed:
            mem_change_events_by_room_id.setdefault(event.room_id, []).append(event)

        newly_joined_rooms = []
        newly_left_rooms = []
        room_entries = []
        invited = []
        for room_id, events in mem_change_events_by_room_id.items():
            logger.debug(
                "Membership changes in %s: [%s]",
                room_id,
                ", ".join(("%s (%s)" % (e.event_id, e.membership) for e in events)),
            )

            non_joins = [e for e in events if e.membership != Membership.JOIN]
            has_join = len(non_joins) != len(events)

            # We want to figure out if we joined the room at some point since
            # the last sync (even if we have since left). This is to make sure
            # we do send down the room, and with full state, where necessary

            old_state_ids = None
            if room_id in sync_result_builder.joined_room_ids and non_joins:
                # Always include if the user (re)joined the room, especially
                # important so that device list changes are calculated correctly.
                # If there are non-join member events, but we are still in the room,
                # then the user must have left and joined
                newly_joined_rooms.append(room_id)

                # User is in the room so we don't need to do the invite/leave checks
                continue

            if room_id in sync_result_builder.joined_room_ids or has_join:
                old_state_ids = await self.get_state_at(room_id, since_token)
                old_mem_ev_id = old_state_ids.get((EventTypes.Member, user_id), None)
                old_mem_ev = None
                if old_mem_ev_id:
                    old_mem_ev = await self.store.get_event(
                        old_mem_ev_id, allow_none=True
                    )

                # debug for #4422
                if has_join:
                    prev_membership = None
                    if old_mem_ev:
                        prev_membership = old_mem_ev.membership
                    issue4422_logger.debug(
                        "Previous membership for room %s with join: %s (event %s)",
                        room_id,
                        prev_membership,
                        old_mem_ev_id,
                    )

                if not old_mem_ev or old_mem_ev.membership != Membership.JOIN:
                    newly_joined_rooms.append(room_id)

            # If user is in the room then we don't need to do the invite/leave checks
            if room_id in sync_result_builder.joined_room_ids:
                continue

            if not non_joins:
                continue

            # Check if we have left the room. This can either be because we were
            # joined before *or* that we since joined and then left.
            if events[-1].membership != Membership.JOIN:
                if has_join:
                    newly_left_rooms.append(room_id)
                else:
                    if not old_state_ids:
                        old_state_ids = await self.get_state_at(room_id, since_token)
                        old_mem_ev_id = old_state_ids.get(
                            (EventTypes.Member, user_id), None
                        )
                        old_mem_ev = None
                        if old_mem_ev_id:
                            old_mem_ev = await self.store.get_event(
                                old_mem_ev_id, allow_none=True
                            )
                    if old_mem_ev and old_mem_ev.membership == Membership.JOIN:
                        newly_left_rooms.append(room_id)

            # Only bother if we're still currently invited
            should_invite = non_joins[-1].membership == Membership.INVITE
            if should_invite:
                if event.sender not in ignored_users:
                    room_sync = InvitedSyncResult(room_id, invite=non_joins[-1])
                    if room_sync:
                        invited.append(room_sync)

            # Always include leave/ban events. Just take the last one.
            # TODO: How do we handle ban -> leave in same batch?
            leave_events = [
                e
                for e in non_joins
                if e.membership in (Membership.LEAVE, Membership.BAN)
            ]

            if leave_events:
                leave_event = leave_events[-1]
                leave_position = await self.store.get_position_for_event(
                    leave_event.event_id
                )

                # If the leave event happened before the since token then we
                # bail.
                if since_token and not leave_position.persisted_after(
                    since_token.room_key
                ):
                    continue

                # We can safely convert the position of the leave event into a
                # stream token as it'll only be used in the context of this
                # room. (c.f. the docstring of `to_room_stream_token`).
                leave_token = since_token.copy_and_replace(
                    "room_key", leave_position.to_room_stream_token()
                )

                # If this is an out of band message, like a remote invite
                # rejection, we include it in the recents batch. Otherwise, we
                # let _load_filtered_recents handle fetching the correct
                # batches.
                #
                # This is all screaming out for a refactor, as the logic here is
                # subtle and the moving parts numerous.
                if leave_event.internal_metadata.is_out_of_band_membership():
                    batch_events = [leave_event]  # type: Optional[List[EventBase]]
                else:
                    batch_events = None

                room_entries.append(
                    RoomSyncResultBuilder(
                        room_id=room_id,
                        rtype="archived",
                        events=batch_events,
                        newly_joined=room_id in newly_joined_rooms,
                        full_state=False,
                        since_token=since_token,
                        upto_token=leave_token,
                    )
                )

        timeline_limit = sync_config.filter_collection.timeline_limit()

        # Get all events for rooms we're currently joined to.
        room_to_events = await self.store.get_room_events_stream_for_rooms(
            room_ids=sync_result_builder.joined_room_ids,
            from_key=since_token.room_key,
            to_key=now_token.room_key,
            limit=timeline_limit + 1,
        )

        # We loop through all room ids, even if there are no new events, in case
        # there are non room events that we need to notify about.
        for room_id in sync_result_builder.joined_room_ids:
            room_entry = room_to_events.get(room_id, None)

            newly_joined = room_id in newly_joined_rooms
            if room_entry:
                events, start_key = room_entry

                prev_batch_token = now_token.copy_and_replace("room_key", start_key)

                entry = RoomSyncResultBuilder(
                    room_id=room_id,
                    rtype="joined",
                    events=events,
                    newly_joined=newly_joined,
                    full_state=False,
                    since_token=None if newly_joined else since_token,
                    upto_token=prev_batch_token,
                )
            else:
                entry = RoomSyncResultBuilder(
                    room_id=room_id,
                    rtype="joined",
                    events=[],
                    newly_joined=newly_joined,
                    full_state=False,
                    since_token=since_token,
                    upto_token=since_token,
                )

            if newly_joined:
                # debugging for https://github.com/matrix-org/synapse/issues/4422
                issue4422_logger.debug(
                    "RoomSyncResultBuilder events for newly joined room %s: %r",
                    room_id,
                    entry.events,
                )
            room_entries.append(entry)

        return _RoomChanges(room_entries, invited, newly_joined_rooms, newly_left_rooms)

    async def _get_all_rooms(
        self, sync_result_builder: "SyncResultBuilder", ignored_users: FrozenSet[str]
    ) -> _RoomChanges:
        """Returns entries for all rooms for the user.

        Args:
            sync_result_builder
            ignored_users: Set of users ignored by user.

        """

        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token
        now_token = sync_result_builder.now_token
        sync_config = sync_result_builder.sync_config

        membership_list = (
            Membership.INVITE,
            Membership.JOIN,
            Membership.LEAVE,
            Membership.BAN,
        )

        room_list = await self.store.get_rooms_for_local_user_where_membership_is(
            user_id=user_id, membership_list=membership_list
        )

        room_entries = []
        invited = []

        for event in room_list:
            if event.membership == Membership.JOIN:
                room_entries.append(
                    RoomSyncResultBuilder(
                        room_id=event.room_id,
                        rtype="joined",
                        events=None,
                        newly_joined=False,
                        full_state=True,
                        since_token=since_token,
                        upto_token=now_token,
                    )
                )
            elif event.membership == Membership.INVITE:
                if event.sender in ignored_users:
                    continue
                invite = await self.store.get_event(event.event_id)
                invited.append(InvitedSyncResult(room_id=event.room_id, invite=invite))
            elif event.membership in (Membership.LEAVE, Membership.BAN):
                # Always send down rooms we were banned or kicked from.
                if not sync_config.filter_collection.include_leave:
                    if event.membership == Membership.LEAVE:
                        if user_id == event.sender:
                            continue

                leave_token = now_token.copy_and_replace(
                    "room_key", RoomStreamToken(None, event.stream_ordering)
                )
                room_entries.append(
                    RoomSyncResultBuilder(
                        room_id=event.room_id,
                        rtype="archived",
                        events=None,
                        newly_joined=False,
                        full_state=True,
                        since_token=since_token,
                        upto_token=leave_token,
                    )
                )

        return _RoomChanges(room_entries, invited, [], [])

    async def _generate_room_entry(
        self,
        sync_result_builder: "SyncResultBuilder",
        ignored_users: FrozenSet[str],
        room_builder: "RoomSyncResultBuilder",
        ephemeral: List[JsonDict],
        tags: Optional[Dict[str, Dict[str, Any]]],
        account_data: Dict[str, JsonDict],
        always_include: bool = False,
    ):
        """Populates the `joined` and `archived` section of `sync_result_builder`
        based on the `room_builder`.

        Args:
            sync_result_builder
            ignored_users: Set of users ignored by user.
            room_builder
            ephemeral: List of new ephemeral events for room
            tags: List of *all* tags for room, or None if there has been
                no change.
            account_data: List of new account data for room
            always_include: Always include this room in the sync response,
                even if empty.
        """
        newly_joined = room_builder.newly_joined
        full_state = (
            room_builder.full_state or newly_joined or sync_result_builder.full_state
        )
        events = room_builder.events

        # We want to shortcut out as early as possible.
        if not (always_include or account_data or ephemeral or full_state):
            if events == [] and tags is None:
                return

        now_token = sync_result_builder.now_token
        sync_config = sync_result_builder.sync_config

        room_id = room_builder.room_id
        since_token = room_builder.since_token
        upto_token = room_builder.upto_token

        batch = await self._load_filtered_recents(
            room_id,
            sync_config,
            now_token=upto_token,
            since_token=since_token,
            potential_recents=events,
            newly_joined_room=newly_joined,
        )

        # Note: `batch` can be both empty and limited here in the case where
        # `_load_filtered_recents` can't find any events the user should see
        # (e.g. due to having ignored the sender of the last 50 events).

        if newly_joined:
            # debug for https://github.com/matrix-org/synapse/issues/4422
            issue4422_logger.debug(
                "Timeline events after filtering in newly-joined room %s: %r",
                room_id,
                batch,
            )

        # When we join the room (or the client requests full_state), we should
        # send down any existing tags. Usually the user won't have tags in a
        # newly joined room, unless either a) they've joined before or b) the
        # tag was added by synapse e.g. for server notice rooms.
        if full_state:
            user_id = sync_result_builder.sync_config.user.to_string()
            tags = await self.store.get_tags_for_room(user_id, room_id)

            # If there aren't any tags, don't send the empty tags list down
            # sync
            if not tags:
                tags = None

        account_data_events = []
        if tags is not None:
            account_data_events.append({"type": "m.tag", "content": {"tags": tags}})

        for account_data_type, content in account_data.items():
            account_data_events.append({"type": account_data_type, "content": content})

        account_data_events = sync_config.filter_collection.filter_room_account_data(
            account_data_events
        )

        ephemeral = sync_config.filter_collection.filter_room_ephemeral(ephemeral)

        if not (
            always_include or batch or account_data_events or ephemeral or full_state
        ):
            return

        state = await self.compute_state_delta(
            room_id, batch, sync_config, since_token, now_token, full_state=full_state
        )

        summary = {}  # type: Optional[JsonDict]

        # we include a summary in room responses when we're lazy loading
        # members (as the client otherwise doesn't have enough info to form
        # the name itself).
        if sync_config.filter_collection.lazy_load_members() and (
            # we recalculate the summary:
            #   if there are membership changes in the timeline, or
            #   if membership has changed during a gappy sync, or
            #   if this is an initial sync.
            any(ev.type == EventTypes.Member for ev in batch.events)
            or (
                # XXX: this may include false positives in the form of LL
                # members which have snuck into state
                batch.limited
                and any(t == EventTypes.Member for (t, k) in state)
            )
            or since_token is None
        ):
            summary = await self.compute_summary(
                room_id, sync_config, batch, state, now_token
            )

        if room_builder.rtype == "joined":
            unread_notifications = {}  # type: Dict[str, int]
            room_sync = JoinedSyncResult(
                room_id=room_id,
                timeline=batch,
                state=state,
                ephemeral=ephemeral,
                account_data=account_data_events,
                unread_notifications=unread_notifications,
                summary=summary,
                unread_count=0,
            )

            if room_sync or always_include:
                notifs = await self.unread_notifs_for_room_id(room_id, sync_config)

                unread_notifications["notification_count"] = notifs["notify_count"]
                unread_notifications["highlight_count"] = notifs["highlight_count"]

                room_sync.unread_count = notifs["unread_count"]

                sync_result_builder.joined.append(room_sync)

            if batch.limited and since_token:
                user_id = sync_result_builder.sync_config.user.to_string()
                logger.debug(
                    "Incremental gappy sync of %s for user %s with %d state events"
                    % (room_id, user_id, len(state))
                )
        elif room_builder.rtype == "archived":
            archived_room_sync = ArchivedSyncResult(
                room_id=room_id,
                timeline=batch,
                state=state,
                account_data=account_data_events,
            )
            if archived_room_sync or always_include:
                sync_result_builder.archived.append(archived_room_sync)
        else:
            raise Exception("Unrecognized rtype: %r", room_builder.rtype)

    async def get_rooms_for_user_at(
        self, user_id: str, room_key: RoomStreamToken
    ) -> FrozenSet[str]:
        """Get set of joined rooms for a user at the given stream ordering.

        The stream ordering *must* be recent, otherwise this may throw an
        exception if older than a month. (This function is called with the
        current token, which should be perfectly fine).

        Args:
            user_id
            stream_ordering

        ReturnValue:
            Set of room_ids the user is in at given stream_ordering.
        """
        joined_rooms = await self.store.get_rooms_for_user_with_stream_ordering(user_id)

        joined_room_ids = set()

        # We need to check that the stream ordering of the join for each room
        # is before the stream_ordering asked for. This might not be the case
        # if the user joins a room between us getting the current token and
        # calling `get_rooms_for_user_with_stream_ordering`.
        # If the membership's stream ordering is after the given stream
        # ordering, we need to go and work out if the user was in the room
        # before.
        for room_id, event_pos in joined_rooms:
            if not event_pos.persisted_after(room_key):
                joined_room_ids.add(room_id)
                continue

            logger.info("User joined room after current token: %s", room_id)

            extrems = await self.store.get_forward_extremeties_for_room(
                room_id, event_pos.stream
            )
            users_in_room = await self.state.get_current_users_in_room(room_id, extrems)
            if user_id in users_in_room:
                joined_room_ids.add(room_id)

        return frozenset(joined_room_ids)


def _action_has_highlight(actions: List[JsonDict]) -> bool:
    for action in actions:
        try:
            if action.get("set_tweak", None) == "highlight":
                return action.get("value", True)
        except AttributeError:
            pass

    return False


def _calculate_state(
    timeline_contains: StateMap[str],
    timeline_start: StateMap[str],
    previous: StateMap[str],
    current: StateMap[str],
    lazy_load_members: bool,
) -> StateMap[str]:
    """Works out what state to include in a sync response.

    Args:
        timeline_contains: state in the timeline
        timeline_start: state at the start of the timeline
        previous: state at the end of the previous sync (or empty dict
            if this is an initial sync)
        current: state at the end of the timeline
        lazy_load_members: whether to return members from timeline_start
            or not.  assumes that timeline_start has already been filtered to
            include only the members the client needs to know about.
    """
    event_id_to_key = {
        e: key
        for key, e in itertools.chain(
            timeline_contains.items(),
            previous.items(),
            timeline_start.items(),
            current.items(),
        )
    }

    c_ids = set(current.values())
    ts_ids = set(timeline_start.values())
    p_ids = set(previous.values())
    tc_ids = set(timeline_contains.values())

    # If we are lazyloading room members, we explicitly add the membership events
    # for the senders in the timeline into the state block returned by /sync,
    # as we may not have sent them to the client before.  We find these membership
    # events by filtering them out of timeline_start, which has already been filtered
    # to only include membership events for the senders in the timeline.
    # In practice, we can do this by removing them from the p_ids list,
    # which is the list of relevant state we know we have already sent to the client.
    # see https://github.com/matrix-org/synapse/pull/2970
    #            /files/efcdacad7d1b7f52f879179701c7e0d9b763511f#r204732809

    if lazy_load_members:
        p_ids.difference_update(
            e for t, e in timeline_start.items() if t[0] == EventTypes.Member
        )

    state_ids = ((c_ids | ts_ids) - p_ids) - tc_ids

    return {event_id_to_key[e]: e for e in state_ids}


@attr.s(slots=True)
class SyncResultBuilder:
    """Used to help build up a new SyncResult for a user

    Attributes:
        sync_config
        full_state: The full_state flag as specified by user
        since_token: The token supplied by user, or None.
        now_token: The token to sync up to.
        joined_room_ids: List of rooms the user is joined to

        # The following mirror the fields in a sync response
        presence (list)
        account_data (list)
        joined (list[JoinedSyncResult])
        invited (list[InvitedSyncResult])
        archived (list[ArchivedSyncResult])
        groups (GroupsSyncResult|None)
        to_device (list)
    """

    sync_config = attr.ib(type=SyncConfig)
    full_state = attr.ib(type=bool)
    since_token = attr.ib(type=Optional[StreamToken])
    now_token = attr.ib(type=StreamToken)
    joined_room_ids = attr.ib(type=FrozenSet[str])

    presence = attr.ib(type=List[JsonDict], default=attr.Factory(list))
    account_data = attr.ib(type=List[JsonDict], default=attr.Factory(list))
    joined = attr.ib(type=List[JoinedSyncResult], default=attr.Factory(list))
    invited = attr.ib(type=List[InvitedSyncResult], default=attr.Factory(list))
    archived = attr.ib(type=List[ArchivedSyncResult], default=attr.Factory(list))
    groups = attr.ib(type=Optional[GroupsSyncResult], default=None)
    to_device = attr.ib(type=List[JsonDict], default=attr.Factory(list))


@attr.s(slots=True)
class RoomSyncResultBuilder:
    """Stores information needed to create either a `JoinedSyncResult` or
    `ArchivedSyncResult`.

    Attributes:
        room_id
        rtype: One of `"joined"` or `"archived"`
        events: List of events to include in the room (more events may be added
            when generating result).
        newly_joined: If the user has newly joined the room
        full_state: Whether the full state should be sent in result
        since_token: Earliest point to return events from, or None
        upto_token: Latest point to return events from.
    """

    room_id = attr.ib(type=str)
    rtype = attr.ib(type=str)
    events = attr.ib(type=Optional[List[EventBase]])
    newly_joined = attr.ib(type=bool)
    full_state = attr.ib(type=bool)
    since_token = attr.ib(type=Optional[StreamToken])
    upto_token = attr.ib(type=StreamToken)
