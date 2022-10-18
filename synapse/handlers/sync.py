# Copyright 2015-2021 The Matrix.org Foundation C.I.C.
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
    AbstractSet,
    Any,
    Collection,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import attr
from prometheus_client import Counter

from synapse.api.constants import EventTypes, Membership
from synapse.api.filtering import FilterCollection
from synapse.api.presence import UserPresenceState
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import EventBase
from synapse.handlers.relations import BundledAggregations
from synapse.logging.context import current_context
from synapse.logging.opentracing import SynapseTags, log_kv, set_tag, start_active_span
from synapse.push.clientformat import format_push_rules_for_user
from synapse.storage.databases.main.event_push_actions import RoomNotifCounts
from synapse.storage.roommember import MemberSummary
from synapse.storage.state import StateFilter
from synapse.types import (
    DeviceListUpdates,
    JsonDict,
    MutableStateMap,
    Requester,
    RoomStreamToken,
    StateMap,
    StreamKeyType,
    StreamToken,
    UserID,
)
from synapse.util.async_helpers import concurrently_execute
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.response_cache import ResponseCache, ResponseCacheContext
from synapse.util.metrics import Measure, measure_func
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

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


SyncRequestKey = Tuple[Any, ...]


@attr.s(slots=True, frozen=True, auto_attribs=True)
class SyncConfig:
    user: UserID
    filter_collection: FilterCollection
    is_guest: bool
    request_key: SyncRequestKey
    device_id: Optional[str]


@attr.s(slots=True, frozen=True, auto_attribs=True)
class TimelineBatch:
    prev_batch: StreamToken
    events: Sequence[EventBase]
    limited: bool
    # A mapping of event ID to the bundled aggregations for the above events.
    # This is only calculated if limited is true.
    bundled_aggregations: Optional[Dict[str, BundledAggregations]] = None

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
@attr.s(slots=True, auto_attribs=True)
class JoinedSyncResult:
    room_id: str
    timeline: TimelineBatch
    state: StateMap[EventBase]
    ephemeral: List[JsonDict]
    account_data: List[JsonDict]
    unread_notifications: JsonDict
    unread_thread_notifications: JsonDict
    summary: Optional[JsonDict]
    unread_count: int

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


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ArchivedSyncResult:
    room_id: str
    timeline: TimelineBatch
    state: StateMap[EventBase]
    account_data: List[JsonDict]

    def __bool__(self) -> bool:
        """Make the result appear empty if there are no updates. This is used
        to tell if room needs to be part of the sync result.
        """
        return bool(self.timeline or self.state or self.account_data)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class InvitedSyncResult:
    room_id: str
    invite: EventBase

    def __bool__(self) -> bool:
        """Invited rooms should always be reported to the client"""
        return True


@attr.s(slots=True, frozen=True, auto_attribs=True)
class KnockedSyncResult:
    room_id: str
    knock: EventBase

    def __bool__(self) -> bool:
        """Knocked rooms should always be reported to the client"""
        return True


@attr.s(slots=True, auto_attribs=True)
class _RoomChanges:
    """The set of room entries to include in the sync, plus the set of joined
    and left room IDs since last sync.
    """

    room_entries: List["RoomSyncResultBuilder"]
    invited: List[InvitedSyncResult]
    knocked: List[KnockedSyncResult]
    newly_joined_rooms: List[str]
    newly_left_rooms: List[str]


@attr.s(slots=True, frozen=True, auto_attribs=True)
class SyncResult:
    """
    Attributes:
        next_batch: Token for the next sync
        presence: List of presence events for the user.
        account_data: List of account_data events for the user.
        joined: JoinedSyncResult for each joined room.
        invited: InvitedSyncResult for each invited room.
        knocked: KnockedSyncResult for each knocked on room.
        archived: ArchivedSyncResult for each archived room.
        to_device: List of direct messages for the device.
        device_lists: List of user_ids whose devices have changed
        device_one_time_keys_count: Dict of algorithm to count for one time keys
            for this device
        device_unused_fallback_key_types: List of key types that have an unused fallback
            key
    """

    next_batch: StreamToken
    presence: List[UserPresenceState]
    account_data: List[JsonDict]
    joined: List[JoinedSyncResult]
    invited: List[InvitedSyncResult]
    knocked: List[KnockedSyncResult]
    archived: List[ArchivedSyncResult]
    to_device: List[JsonDict]
    device_lists: DeviceListUpdates
    device_one_time_keys_count: JsonDict
    device_unused_fallback_key_types: List[str]

    def __bool__(self) -> bool:
        """Make the result appear empty if there are no updates. This is used
        to tell if the notifier needs to wait for more events when polling for
        events.
        """
        return bool(
            self.presence
            or self.joined
            or self.invited
            or self.knocked
            or self.archived
            or self.account_data
            or self.to_device
            or self.device_lists
        )


class SyncHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs_config = hs.config
        self.store = hs.get_datastores().main
        self.notifier = hs.get_notifier()
        self.presence_handler = hs.get_presence_handler()
        self._relations_handler = hs.get_relations_handler()
        self.event_sources = hs.get_event_sources()
        self.clock = hs.get_clock()
        self.state = hs.get_state_handler()
        self.auth_blocking = hs.get_auth_blocking()
        self._storage_controllers = hs.get_storage_controllers()
        self._state_storage_controller = self._storage_controllers.state
        self._device_handler = hs.get_device_handler()

        # TODO: flush cache entries on subsequent sync request.
        #    Once we get the next /sync request (ie, one with the same access token
        #    that sets 'since' to 'next_batch'), we know that device won't need a
        #    cached result any more, and we could flush the entry from the cache to save
        #    memory.
        self.response_cache: ResponseCache[SyncRequestKey] = ResponseCache(
            hs.get_clock(),
            "sync",
            timeout_ms=hs.config.caches.sync_response_cache_duration,
        )

        # ExpiringCache((User, Device)) -> LruCache(user_id => event_id)
        self.lazy_loaded_members_cache: ExpiringCache[
            Tuple[str, Optional[str]], LruCache[str, str]
        ] = ExpiringCache(
            "lazy_loaded_members_cache",
            self.clock,
            max_len=0,
            expiry_ms=LAZY_LOADED_MEMBERS_CACHE_MAX_AGE,
        )

        self.rooms_to_exclude = hs.config.server.rooms_to_exclude_from_sync

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
        await self.auth_blocking.check_auth_blocking(requester=requester)

        res = await self.response_cache.wrap(
            sync_config.request_key,
            self._wait_for_sync_for_user,
            sync_config,
            since_token,
            timeout,
            full_state,
            cache_context=True,
        )
        logger.debug("Returning sync response for %s", user_id)
        return res

    async def _wait_for_sync_for_user(
        self,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken],
        timeout: int,
        full_state: bool,
        cache_context: ResponseCacheContext[SyncRequestKey],
    ) -> SyncResult:
        """The start of the machinery that produces a /sync response.

        See https://spec.matrix.org/v1.1/client-server-api/#syncing for full details.

        This method does high-level bookkeeping:
        - tracking the kind of sync in the logging context
        - deleting any to_device messages whose delivery has been acknowledged.
        - deciding if we should dispatch an instant or delayed response
        - marking the sync as being lazily loaded, if appropriate

        Computing the body of the response begins in the next method,
        `current_sync_for_user`.
        """
        if since_token is None:
            sync_type = "initial_sync"
        elif full_state:
            sync_type = "full_state_sync"
        else:
            sync_type = "incremental_sync"

        context = current_context()
        if context:
            context.tag = sync_type

        # if we have a since token, delete any to-device messages before that token
        # (since we now know that the device has received them)
        if since_token is not None:
            since_stream_id = since_token.to_device_key
            deleted = await self.store.delete_messages_for_device(
                sync_config.user.to_string(), sync_config.device_id, since_stream_id
            )
            logger.debug(
                "Deleted %d to-device messages up to %d", deleted, since_stream_id
            )

        if timeout == 0 or since_token is None or full_state:
            # we are going to return immediately, so don't bother calling
            # notifier.wait_for_events.
            result: SyncResult = await self.current_sync_for_user(
                sync_config, since_token, full_state=full_state
            )
        else:
            # Otherwise, we wait for something to happen and report it to the user.
            async def current_sync_callback(
                before_token: StreamToken, after_token: StreamToken
            ) -> SyncResult:
                return await self.current_sync_for_user(sync_config, since_token)

            result = await self.notifier.wait_for_events(
                sync_config.user.to_string(),
                timeout,
                current_sync_callback,
                from_token=since_token,
            )

            # if nothing has happened in any of the users' rooms since /sync was called,
            # the resultant next_batch will be the same as since_token (since the result
            # is generated when wait_for_events is first called, and not regenerated
            # when wait_for_events times out).
            #
            # If that happens, we mustn't cache it, so that when the client comes back
            # with the same cache token, we don't immediately return the same empty
            # result, causing a tightloop. (#8518)
            if result.next_batch == since_token:
                cache_context.should_cache = False

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
        """Generates the response body of a sync result, represented as a SyncResult.

        This is a wrapper around `generate_sync_result` which starts an open tracing
        span to track the sync. See `generate_sync_result` for the next part of your
        indoctrination.
        """
        with start_active_span("sync.current_sync_for_user"):
            log_kv({"since_token": since_token})
            sync_result = await self.generate_sync_result(
                sync_config, since_token, full_state
            )

            set_tag(SynapseTags.SYNC_RESULT, bool(sync_result))
            return sync_result

    async def push_rules_for_user(self, user: UserID) -> Dict[str, Dict[str, list]]:
        user_id = user.to_string()
        rules_raw = await self.store.get_push_rules_for_user(user_id)
        rules = format_push_rules_for_user(user, rules_raw)
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

            typing_source = self.event_sources.sources.typing
            typing, typing_key = await typing_source.get_new_events(
                user=sync_config.user,
                from_key=typing_key,
                limit=sync_config.filter_collection.ephemeral_limit(),
                room_ids=room_ids,
                is_guest=sync_config.is_guest,
            )
            now_token = now_token.copy_and_replace(StreamKeyType.TYPING, typing_key)

            ephemeral_by_room: JsonDict = {}

            for event in typing:
                # we want to exclude the room_id from the event, but modifying the
                # result returned by the event source is poor form (it might cache
                # the object)
                room_id = event["room_id"]
                event_copy = {k: v for (k, v) in event.items() if k != "room_id"}
                ephemeral_by_room.setdefault(room_id, []).append(event_copy)

            receipt_key = since_token.receipt_key if since_token else 0

            receipt_source = self.event_sources.sources.receipt
            receipts, receipt_key = await receipt_source.get_new_events(
                user=sync_config.user,
                from_key=receipt_key,
                limit=sync_config.filter_collection.ephemeral_limit(),
                room_ids=room_ids,
                is_guest=sync_config.is_guest,
            )
            now_token = now_token.copy_and_replace(StreamKeyType.RECEIPT, receipt_key)

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

            log_kv({"limited": limited})

            if potential_recents:
                recents = await sync_config.filter_collection.filter_room_timeline(
                    potential_recents
                )
                log_kv({"recents_after_sync_filtering": len(recents)})

                # We check if there are any state events, if there are then we pass
                # all current state events to the filter_events function. This is to
                # ensure that we always include current state in the timeline
                current_state_ids: FrozenSet[str] = frozenset()
                if any(e.is_state() for e in recents):
                    # FIXME(faster_joins): We use the partial state here as
                    # we don't want to block `/sync` on finishing a lazy join.
                    # Which should be fine once
                    # https://github.com/matrix-org/synapse/issues/12989 is resolved,
                    # since we shouldn't reach here anymore?
                    # Note that we use the current state as a whitelist for filtering
                    # `recents`, so partial state is only a problem when a membership
                    # event turns up in `recents` but has not made it into the current
                    # state.
                    current_state_ids_map = (
                        await self.store.get_partial_current_state_ids(room_id)
                    )
                    current_state_ids = frozenset(current_state_ids_map.values())

                recents = await filter_events_for_client(
                    self._storage_controllers,
                    sync_config.user.to_string(),
                    recents,
                    always_include_ids=current_state_ids,
                )
                log_kv({"recents_after_visibility_filtering": len(recents)})
            else:
                recents = []

            if not limited or block_all_timeline:
                prev_batch_token = now_token
                if recents:
                    room_key = recents[0].internal_metadata.before
                    prev_batch_token = now_token.copy_and_replace(
                        StreamKeyType.ROOM, room_key
                    )

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
                # in topological ordering.
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

                log_kv({"loaded_recents": len(events)})

                loaded_recents = (
                    await sync_config.filter_collection.filter_room_timeline(events)
                )

                log_kv({"loaded_recents_after_sync_filtering": len(loaded_recents)})

                # We check if there are any state events, if there are then we pass
                # all current state events to the filter_events function. This is to
                # ensure that we always include current state in the timeline
                current_state_ids = frozenset()
                if any(e.is_state() for e in loaded_recents):
                    # FIXME(faster_joins): We use the partial state here as
                    # we don't want to block `/sync` on finishing a lazy join.
                    # Which should be fine once
                    # https://github.com/matrix-org/synapse/issues/12989 is resolved,
                    # since we shouldn't reach here anymore?
                    # Note that we use the current state as a whitelist for filtering
                    # `loaded_recents`, so partial state is only a problem when a
                    # membership event turns up in `loaded_recents` but has not made it
                    # into the current state.
                    current_state_ids_map = (
                        await self.store.get_partial_current_state_ids(room_id)
                    )
                    current_state_ids = frozenset(current_state_ids_map.values())

                loaded_recents = await filter_events_for_client(
                    self._storage_controllers,
                    sync_config.user.to_string(),
                    loaded_recents,
                    always_include_ids=current_state_ids,
                )

                log_kv({"loaded_recents_after_client_filtering": len(loaded_recents)})

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

            prev_batch_token = now_token.copy_and_replace(StreamKeyType.ROOM, room_key)

        # Don't bother to bundle aggregations if the timeline is unlimited,
        # as clients will have all the necessary information.
        bundled_aggregations = None
        if limited or newly_joined_room:
            bundled_aggregations = (
                await self._relations_handler.get_bundled_aggregations(
                    recents, sync_config.user.to_string()
                )
            )

        return TimelineBatch(
            events=recents,
            prev_batch=prev_batch_token,
            limited=limited or newly_joined_room,
            bundled_aggregations=bundled_aggregations,
        )

    async def get_state_after_event(
        self,
        event_id: str,
        state_filter: Optional[StateFilter] = None,
        await_full_state: bool = True,
    ) -> StateMap[str]:
        """
        Get the room state after the given event

        Args:
            event_id: event of interest
            state_filter: The state filter used to fetch state from the database.
            await_full_state: if `True`, will block if we do not yet have complete state
                at the event and `state_filter` is not satisfied by partial state.
                Defaults to `True`.
        """
        state_ids = await self._state_storage_controller.get_state_ids_for_event(
            event_id,
            state_filter=state_filter or StateFilter.all(),
            await_full_state=await_full_state,
        )

        # using get_metadata_for_events here (instead of get_event) sidesteps an issue
        # with redactions: if `event_id` is a redaction event, and we don't have the
        # original (possibly because it got purged), get_event will refuse to return
        # the redaction event, which isn't terribly helpful here.
        #
        # (To be fair, in that case we could assume it's *not* a state event, and
        # therefore we don't need to worry about it. But still, it seems cleaner just
        # to pull the metadata.)
        m = (await self.store.get_metadata_for_events([event_id]))[event_id]
        if m.state_key is not None and m.rejection_reason is None:
            state_ids = dict(state_ids)
            state_ids[(m.event_type, m.state_key)] = event_id

        return state_ids

    async def get_state_at(
        self,
        room_id: str,
        stream_position: StreamToken,
        state_filter: Optional[StateFilter] = None,
        await_full_state: bool = True,
    ) -> StateMap[str]:
        """Get the room state at a particular stream position

        Args:
            room_id: room for which to get state
            stream_position: point at which to get state
            state_filter: The state filter used to fetch state from the database.
            await_full_state: if `True`, will block if we do not yet have complete state
                at the last event in the room before `stream_position` and
                `state_filter` is not satisfied by partial state. Defaults to `True`.
        """
        # FIXME: This gets the state at the latest event before the stream ordering,
        # which might not be the same as the "current state" of the room at the time
        # of the stream token if there were multiple forward extremities at the time.
        last_event_id = await self.store.get_last_event_in_room_before_stream_ordering(
            room_id,
            end_token=stream_position.room_key,
        )

        if last_event_id:
            state = await self.get_state_after_event(
                last_event_id,
                state_filter=state_filter or StateFilter.all(),
                await_full_state=await_full_state,
            )

        else:
            # no events in this room - so presumably no state
            state = {}

            # (erikj) This should be rarely hit, but we've had some reports that
            # we get more state down gappy syncs than we should, so let's add
            # some logging.
            logger.info(
                "Failed to find any events in room %s at %s",
                room_id,
                stream_position.room_key,
            )
        return state

    async def compute_summary(
        self,
        room_id: str,
        sync_config: SyncConfig,
        batch: TimelineBatch,
        state: MutableStateMap[EventBase],
        now_token: StreamToken,
    ) -> Optional[JsonDict]:
        """Works out a room summary block for this room, summarising the number
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
        state_ids = await self._state_storage_controller.get_state_ids_for_event(
            last_event.event_id,
            state_filter=StateFilter.from_types(
                [(EventTypes.Name, ""), (EventTypes.CanonicalAlias, "")]
            ),
        )

        # this is heavily cached, thus: fast.
        details = await self.store.get_room_summary(room_id)

        name_id = state_ids.get((EventTypes.Name, ""))
        canonical_alias_id = state_ids.get((EventTypes.CanonicalAlias, ""))

        summary: JsonDict = {}
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

    def get_lazy_loaded_members_cache(
        self, cache_key: Tuple[str, Optional[str]]
    ) -> LruCache[str, str]:
        cache: Optional[LruCache[str, str]] = self.lazy_loaded_members_cache.get(
            cache_key
        )
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
        """Works out the difference in state between the end of the previous sync and
        the start of the timeline.

        Args:
            room_id:
            batch: The timeline batch for the room that will be sent to the user.
            sync_config:
            since_token: Token of the end of the previous batch. May be `None`.
            now_token: Token of the end of the current batch.
            full_state: Whether to force returning the full state.
                `lazy_load_members` still applies when `full_state` is `True`.

        Returns:
            The state to return in the sync response for the room.

            Clients will overlay this onto the state at the end of the previous sync to
            arrive at the state at the start of the timeline.

            Clients will then overlay state events in the timeline to arrive at the
            state at the end of the timeline, in preparation for the next sync.
        """
        # TODO(mjark) Check if the state events were received by the server
        # after the previous sync, since we need to include those state
        # updates even if they occurred logically before the previous event.
        # TODO(mjark) Check for new redactions in the state events.

        with Measure(self.clock, "compute_state_delta"):
            # The memberships needed for events in the timeline.
            # Only calculated when `lazy_load_members` is on.
            members_to_fetch: Optional[Set[str]] = None

            # A dictionary mapping user IDs to the first event in the timeline sent by
            # them. Only calculated when `lazy_load_members` is on.
            first_event_by_sender_map: Optional[Dict[str, EventBase]] = None

            # The contribution to the room state from state events in the timeline.
            # Only contains the last event for any given state key.
            timeline_state: StateMap[str]

            lazy_load_members = sync_config.filter_collection.lazy_load_members()
            include_redundant_members = (
                sync_config.filter_collection.include_redundant_members()
            )

            if lazy_load_members:
                # We only request state for the members needed to display the
                # timeline:

                timeline_state = {}

                members_to_fetch = set()
                first_event_by_sender_map = {}
                for event in batch.events:
                    # Build the map from user IDs to the first timeline event they sent.
                    if event.sender not in first_event_by_sender_map:
                        first_event_by_sender_map[event.sender] = event

                    # We need the event's sender, unless their membership was in a
                    # previous timeline event.
                    if (EventTypes.Member, event.sender) not in timeline_state:
                        members_to_fetch.add(event.sender)
                    # FIXME: we also care about invite targets etc.

                    if event.is_state():
                        timeline_state[(event.type, event.state_key)] = event.event_id

                if full_state:
                    # always make sure we LL ourselves so we know we're in the room
                    # (if we are) to fix https://github.com/vector-im/riot-web/issues/7209
                    # We only need apply this on full state syncs given we disabled
                    # LL for incr syncs in #3840.
                    members_to_fetch.add(sync_config.user.to_string())

                state_filter = StateFilter.from_lazy_load_member_list(members_to_fetch)

                # We are happy to use partial state to compute the `/sync` response.
                # Since partial state may not include the lazy-loaded memberships we
                # require, we fix up the state response afterwards with memberships from
                # auth events.
                await_full_state = False
            else:
                timeline_state = {
                    (event.type, event.state_key): event.event_id
                    for event in batch.events
                    if event.is_state()
                }

                state_filter = StateFilter.all()
                await_full_state = True

            # Now calculate the state to return in the sync response for the room.
            # This is more or less the change in state between the end of the previous
            # sync's timeline and the start of the current sync's timeline.
            # See the docstring above for details.
            state_ids: StateMap[str]

            if full_state:
                if batch:
                    state_at_timeline_end = (
                        await self._state_storage_controller.get_state_ids_for_event(
                            batch.events[-1].event_id,
                            state_filter=state_filter,
                            await_full_state=await_full_state,
                        )
                    )

                    state_at_timeline_start = (
                        await self._state_storage_controller.get_state_ids_for_event(
                            batch.events[0].event_id,
                            state_filter=state_filter,
                            await_full_state=await_full_state,
                        )
                    )

                else:
                    state_at_timeline_end = await self.get_state_at(
                        room_id,
                        stream_position=now_token,
                        state_filter=state_filter,
                        await_full_state=await_full_state,
                    )

                    state_at_timeline_start = state_at_timeline_end

                state_ids = _calculate_state(
                    timeline_contains=timeline_state,
                    timeline_start=state_at_timeline_start,
                    timeline_end=state_at_timeline_end,
                    previous_timeline_end={},
                    lazy_load_members=lazy_load_members,
                )
            elif batch.limited:
                if batch:
                    state_at_timeline_start = (
                        await self._state_storage_controller.get_state_ids_for_event(
                            batch.events[0].event_id,
                            state_filter=state_filter,
                            await_full_state=await_full_state,
                        )
                    )
                else:
                    # We can get here if the user has ignored the senders of all
                    # the recent events.
                    state_at_timeline_start = await self.get_state_at(
                        room_id,
                        stream_position=now_token,
                        state_filter=state_filter,
                        await_full_state=await_full_state,
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
                    room_id,
                    stream_position=since_token,
                    state_filter=state_filter,
                    await_full_state=await_full_state,
                )

                if batch:
                    state_at_timeline_end = (
                        await self._state_storage_controller.get_state_ids_for_event(
                            batch.events[-1].event_id,
                            state_filter=state_filter,
                            await_full_state=await_full_state,
                        )
                    )
                else:
                    # We can get here if the user has ignored the senders of all
                    # the recent events.
                    state_at_timeline_end = await self.get_state_at(
                        room_id,
                        stream_position=now_token,
                        state_filter=state_filter,
                        await_full_state=await_full_state,
                    )

                state_ids = _calculate_state(
                    timeline_contains=timeline_state,
                    timeline_start=state_at_timeline_start,
                    timeline_end=state_at_timeline_end,
                    previous_timeline_end=state_at_previous_sync,
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

                        state_ids = await self._state_storage_controller.get_state_ids_for_event(
                            batch.events[0].event_id,
                            # we only want members!
                            state_filter=StateFilter.from_types(
                                (EventTypes.Member, member)
                                for member in members_to_fetch
                            ),
                            await_full_state=False,
                        )

            # If we only have partial state for the room, `state_ids` may be missing the
            # memberships we wanted. We attempt to find some by digging through the auth
            # events of timeline events.
            if lazy_load_members and await self.store.is_partial_state_room(room_id):
                assert members_to_fetch is not None
                assert first_event_by_sender_map is not None

                additional_state_ids = (
                    await self._find_missing_partial_state_memberships(
                        room_id, members_to_fetch, first_event_by_sender_map, state_ids
                    )
                )
                state_ids = {**state_ids, **additional_state_ids}

            # At this point, if `lazy_load_members` is enabled, `state_ids` includes
            # the memberships of all event senders in the timeline. This is because we
            # may not have sent the memberships in a previous sync.

            # When `include_redundant_members` is on, we send all the lazy-loaded
            # memberships of event senders. Otherwise we make an effort to limit the set
            # of memberships we send to those that we have not already sent to this client.
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

        state: Dict[str, EventBase] = {}
        if state_ids:
            state = await self.store.get_events(list(state_ids.values()))

        return {
            (e.type, e.state_key): e
            for e in await sync_config.filter_collection.filter_room_state(
                list(state.values())
            )
            if e.type != EventTypes.Aliases  # until MSC2261 or alternative solution
        }

    async def _find_missing_partial_state_memberships(
        self,
        room_id: str,
        members_to_fetch: Collection[str],
        events_with_membership_auth: Mapping[str, EventBase],
        found_state_ids: StateMap[str],
    ) -> StateMap[str]:
        """Finds missing memberships from a set of auth events and returns them as a
        state map.

        Args:
            room_id: The partial state room to find the remaining memberships for.
            members_to_fetch: The memberships to find.
            events_with_membership_auth: A mapping from user IDs to events whose auth
                events would contain their prior membership, if one exists.
                Note that join events will not cite a prior membership if a user has
                never been in a room before.
            found_state_ids: A dict from (type, state_key) -> state_event_id, containing
                memberships that have been previously found. Entries in
                `members_to_fetch` that have a membership in `found_state_ids` are
                ignored.

        Returns:
            A dict from ("m.room.member", state_key) -> state_event_id, containing the
            memberships missing from `found_state_ids`.

            When `events_with_membership_auth` contains a join event for a given user
            which does not cite a prior membership, no membership is returned for that
            user.

        Raises:
            KeyError: if `events_with_membership_auth` does not have an entry for a
                missing membership. Memberships in `found_state_ids` do not need an
                entry in `events_with_membership_auth`.
        """
        additional_state_ids: MutableStateMap[str] = {}

        # Tracks the missing members for logging purposes.
        missing_members = set()

        # Identify memberships missing from `found_state_ids` and pick out the auth
        # events in which to look for them.
        auth_event_ids: Set[str] = set()
        for member in members_to_fetch:
            if (EventTypes.Member, member) in found_state_ids:
                continue

            event_with_membership_auth = events_with_membership_auth[member]
            is_join = (
                event_with_membership_auth.is_state()
                and event_with_membership_auth.type == EventTypes.Member
                and event_with_membership_auth.state_key == member
                and event_with_membership_auth.content.get("membership")
                == Membership.JOIN
            )
            if not is_join:
                # The event must include the desired membership as an auth event, unless
                # it's the first join event for a given user.
                missing_members.add(member)
            auth_event_ids.update(event_with_membership_auth.auth_event_ids())

        auth_events = await self.store.get_events(auth_event_ids)

        # Run through the missing memberships once more, picking out the memberships
        # from the pile of auth events we have just fetched.
        for member in members_to_fetch:
            if (EventTypes.Member, member) in found_state_ids:
                continue

            event_with_membership_auth = events_with_membership_auth[member]

            # Dig through the auth events to find the desired membership.
            for auth_event_id in event_with_membership_auth.auth_event_ids():
                # We only store events once we have all their auth events,
                # so the auth event must be in the pile we have just
                # fetched.
                auth_event = auth_events[auth_event_id]

                if (
                    auth_event.type == EventTypes.Member
                    and auth_event.state_key == member
                ):
                    missing_members.discard(member)
                    additional_state_ids[
                        (EventTypes.Member, member)
                    ] = auth_event.event_id
                    break

        if missing_members:
            # There really shouldn't be any missing memberships now. Either:
            #  * we couldn't find an auth event, which shouldn't happen because we do
            #    not persist events with persisting their auth events first, or
            #  * the set of auth events did not contain a membership we wanted, which
            #    means our caller didn't compute the events in `members_to_fetch`
            #    correctly, or we somehow accepted an event whose auth events were
            #    dodgy.
            logger.error(
                "Failed to find memberships for %s in partial state room "
                "%s in the auth events of %s.",
                missing_members,
                room_id,
                [
                    events_with_membership_auth[member].event_id
                    for member in missing_members
                ],
            )

        return additional_state_ids

    async def unread_notifs_for_room_id(
        self, room_id: str, sync_config: SyncConfig
    ) -> RoomNotifCounts:
        with Measure(self.clock, "unread_notifs_for_room_id"):

            return await self.store.get_unread_event_push_actions_by_room_for_user(
                room_id,
                sync_config.user.to_string(),
            )

    async def generate_sync_result(
        self,
        sync_config: SyncConfig,
        since_token: Optional[StreamToken] = None,
        full_state: bool = False,
    ) -> SyncResult:
        """Generates the response body of a sync result.

        This is represented by a `SyncResult` struct, which is built from small pieces
        using a `SyncResultBuilder`. See also
            https://spec.matrix.org/v1.1/client-server-api/#get_matrixclientv3sync
        the `sync_result_builder` is passed as a mutable ("inout") parameter to various
        helper functions. These retrieve and process the data which forms the sync body,
        often writing to the `sync_result_builder` to store their output.

        At the end, we transfer data from the `sync_result_builder` to a new `SyncResult`
        instance to signify that the sync calculation is complete.
        """

        user_id = sync_config.user.to_string()
        app_service = self.store.get_app_service_by_user_id(user_id)
        if app_service:
            # We no longer support AS users using /sync directly.
            # See https://github.com/matrix-org/matrix-doc/issues/1144
            raise NotImplementedError()

        # Note: we get the users room list *before* we get the current token, this
        # avoids checking back in history if rooms are joined after the token is fetched.
        token_before_rooms = self.event_sources.get_current_token()
        mutable_joined_room_ids = set(await self.store.get_rooms_for_user(user_id))

        # NB: The now_token gets changed by some of the generate_sync_* methods,
        # this is due to some of the underlying streams not supporting the ability
        # to query up to a given point.
        # Always use the `now_token` in `SyncResultBuilder`
        now_token = self.event_sources.get_current_token()
        log_kv({"now_token": now_token})

        # Since we fetched the users room list before the token, there's a small window
        # during which membership events may have been persisted, so we fetch these now
        # and modify the joined room list for any changes between the get_rooms_for_user
        # call and the get_current_token call.
        membership_change_events = []
        if since_token:
            membership_change_events = await self.store.get_membership_changes_for_user(
                user_id, since_token.room_key, now_token.room_key, self.rooms_to_exclude
            )

            mem_last_change_by_room_id: Dict[str, EventBase] = {}
            for event in membership_change_events:
                mem_last_change_by_room_id[event.room_id] = event

            # For the latest membership event in each room found, add/remove the room ID
            # from the joined room list accordingly. In this case we only care if the
            # latest change is JOIN.

            for room_id, event in mem_last_change_by_room_id.items():
                assert event.internal_metadata.stream_ordering
                if (
                    event.internal_metadata.stream_ordering
                    < token_before_rooms.room_key.stream
                ):
                    continue

                logger.info(
                    "User membership change between getting rooms and current token: %s %s %s",
                    user_id,
                    event.membership,
                    room_id,
                )
                # User joined a room - we have to then check the room state to ensure we
                # respect any bans if there's a race between the join and ban events.
                if event.membership == Membership.JOIN:
                    user_ids_in_room = await self.store.get_users_in_room(room_id)
                    if user_id in user_ids_in_room:
                        mutable_joined_room_ids.add(room_id)
                # The user left the room, or left and was re-invited but not joined yet
                else:
                    mutable_joined_room_ids.discard(room_id)

        # Now we have our list of joined room IDs, exclude as configured and freeze
        joined_room_ids = frozenset(
            (
                room_id
                for room_id in mutable_joined_room_ids
                if room_id not in self.rooms_to_exclude
            )
        )

        logger.debug(
            "Calculating sync response for %r between %s and %s",
            sync_config.user,
            since_token,
            now_token,
        )

        sync_result_builder = SyncResultBuilder(
            sync_config,
            full_state,
            since_token=since_token,
            now_token=now_token,
            joined_room_ids=joined_room_ids,
            membership_change_events=membership_change_events,
        )

        logger.debug("Fetching account data")

        account_data_by_room = await self._generate_sync_entry_for_account_data(
            sync_result_builder
        )

        logger.debug("Fetching room data")

        res = await self._generate_sync_entry_for_rooms(
            sync_result_builder, account_data_by_room
        )
        newly_joined_rooms, newly_joined_or_invited_or_knocked_users, _, _ = res
        _, _, newly_left_rooms, newly_left_users = res

        block_all_presence_data = (
            since_token is None and sync_config.filter_collection.blocks_all_presence()
        )
        if self.hs_config.server.use_presence and not block_all_presence_data:
            logger.debug("Fetching presence data")
            await self._generate_sync_entry_for_presence(
                sync_result_builder,
                newly_joined_rooms,
                newly_joined_or_invited_or_knocked_users,
            )

        logger.debug("Fetching to-device data")
        await self._generate_sync_entry_for_to_device(sync_result_builder)

        device_lists = await self._generate_sync_entry_for_device_list(
            sync_result_builder,
            newly_joined_rooms=newly_joined_rooms,
            newly_joined_or_invited_or_knocked_users=newly_joined_or_invited_or_knocked_users,
            newly_left_rooms=newly_left_rooms,
            newly_left_users=newly_left_users,
        )

        logger.debug("Fetching OTK data")
        device_id = sync_config.device_id
        one_time_key_counts: JsonDict = {}
        unused_fallback_key_types: List[str] = []
        if device_id:
            # TODO: We should have a way to let clients differentiate between the states of:
            #   * no change in OTK count since the provided since token
            #   * the server has zero OTKs left for this device
            #  Spec issue: https://github.com/matrix-org/matrix-doc/issues/3298
            one_time_key_counts = await self.store.count_e2e_one_time_keys(
                user_id, device_id
            )
            unused_fallback_key_types = (
                await self.store.get_e2e_unused_fallback_key_types(user_id, device_id)
            )

        num_events = 0

        # debug for https://github.com/matrix-org/synapse/issues/9424
        for joined_room in sync_result_builder.joined:
            num_events += len(joined_room.timeline.events)

        log_kv(
            {
                "joined_rooms_in_result": len(sync_result_builder.joined),
                "events_in_result": num_events,
            }
        )

        logger.debug("Sync response calculation complete")
        return SyncResult(
            presence=sync_result_builder.presence,
            account_data=sync_result_builder.account_data,
            joined=sync_result_builder.joined,
            invited=sync_result_builder.invited,
            knocked=sync_result_builder.knocked,
            archived=sync_result_builder.archived,
            to_device=sync_result_builder.to_device,
            device_lists=device_lists,
            device_one_time_keys_count=one_time_key_counts,
            device_unused_fallback_key_types=unused_fallback_key_types,
            next_batch=sync_result_builder.now_token,
        )

    @measure_func("_generate_sync_entry_for_device_list")
    async def _generate_sync_entry_for_device_list(
        self,
        sync_result_builder: "SyncResultBuilder",
        newly_joined_rooms: AbstractSet[str],
        newly_joined_or_invited_or_knocked_users: AbstractSet[str],
        newly_left_rooms: AbstractSet[str],
        newly_left_users: AbstractSet[str],
    ) -> DeviceListUpdates:
        """Generate the DeviceListUpdates section of sync

        Args:
            sync_result_builder
            newly_joined_rooms: Set of rooms user has joined since previous sync
            newly_joined_or_invited_or_knocked_users: Set of users that have joined,
                been invited to a room or are knocking on a room since
                previous sync.
            newly_left_rooms: Set of rooms user has left since previous sync
            newly_left_users: Set of users that have left a room we're in since
                previous sync
        """

        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token

        # Take a copy since these fields will be mutated later.
        newly_joined_or_invited_or_knocked_users = set(
            newly_joined_or_invited_or_knocked_users
        )
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

            users_that_have_changed = set()

            joined_rooms = sync_result_builder.joined_room_ids

            # Step 1a, check for changes in devices of users we share a room
            # with
            #
            # We do this in two different ways depending on what we have cached.
            # If we already have a list of all the user that have changed since
            # the last sync then it's likely more efficient to compare the rooms
            # they're in with the rooms the syncing user is in.
            #
            # If we don't have that info cached then we get all the users that
            # share a room with our user and check if those users have changed.
            changed_users = self.store.get_cached_device_list_changes(
                since_token.device_list_key
            )
            if changed_users is not None:
                result = await self.store.get_rooms_for_users(changed_users)

                for changed_user_id, entries in result.items():
                    # Check if the changed user shares any rooms with the user,
                    # or if the changed user is the syncing user (as we always
                    # want to include device list updates of their own devices).
                    if user_id == changed_user_id or any(
                        rid in joined_rooms for rid in entries
                    ):
                        users_that_have_changed.add(changed_user_id)
            else:
                users_that_have_changed = (
                    await self._device_handler.get_device_changes_in_shared_rooms(
                        user_id,
                        sync_result_builder.joined_room_ids,
                        from_token=since_token,
                    )
                )

            # Step 1b, check for newly joined rooms
            for room_id in newly_joined_rooms:
                joined_users = await self.store.get_users_in_room(room_id)
                newly_joined_or_invited_or_knocked_users.update(joined_users)

            # TODO: Check that these users are actually new, i.e. either they
            # weren't in the previous sync *or* they left and rejoined.
            users_that_have_changed.update(newly_joined_or_invited_or_knocked_users)

            user_signatures_changed = (
                await self.store.get_users_whose_signatures_changed(
                    user_id, since_token.device_list_key
                )
            )
            users_that_have_changed.update(user_signatures_changed)

            # Now find users that we no longer track
            for room_id in newly_left_rooms:
                left_users = await self.store.get_users_in_room(room_id)
                newly_left_users.update(left_users)

            # Remove any users that we still share a room with.
            left_users_rooms = await self.store.get_rooms_for_users(newly_left_users)
            for user_id, entries in left_users_rooms.items():
                if any(rid in joined_rooms for rid in entries):
                    newly_left_users.discard(user_id)

            return DeviceListUpdates(
                changed=users_that_have_changed, left=newly_left_users
            )
        else:
            return DeviceListUpdates()

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

        if device_id is not None and since_stream_id != int(now_token.to_device_key):
            messages, stream_id = await self.store.get_messages_for_device(
                user_id, device_id, since_stream_id, now_token.to_device_key
            )

            for message in messages:
                # We pop here as we shouldn't be sending the message ID down
                # `/sync`
                message_id = message.pop("message_id", None)
                if message_id:
                    set_tag(SynapseTags.TO_DEVICE_MESSAGE_ID, message_id)

            logger.debug(
                "Returning %d to-device messages between %d and %d (current token: %d)",
                len(messages),
                since_stream_id,
                stream_id,
                now_token.to_device_key,
            )
            sync_result_builder.now_token = now_token.copy_and_replace(
                StreamKeyType.TO_DEVICE, stream_id
            )
            sync_result_builder.to_device = messages
        else:
            sync_result_builder.to_device = []

    async def _generate_sync_entry_for_account_data(
        self, sync_result_builder: "SyncResultBuilder"
    ) -> Dict[str, Dict[str, JsonDict]]:
        """Generates the account data portion of the sync response.

        Account data (called "Client Config" in the spec) can be set either globally
        or for a specific room. Account data consists of a list of events which
        accumulate state, much like a room.

        This function retrieves global and per-room account data. The former is written
        to the given `sync_result_builder`. The latter is returned directly, to be
        later written to the `sync_result_builder` on a room-by-room basis.

        Args:
            sync_result_builder

        Returns:
            A dictionary whose keys (room ids) map to the per room account data for that
            room.
        """
        sync_config = sync_result_builder.sync_config
        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token

        if since_token and not sync_result_builder.full_state:
            (
                global_account_data,
                account_data_by_room,
            ) = await self.store.get_updated_account_data_for_user(
                user_id, since_token.account_data_key
            )

            push_rules_changed = await self.store.have_push_rules_changed_for_user(
                user_id, int(since_token.push_rules_key)
            )

            if push_rules_changed:
                global_account_data["m.push_rules"] = await self.push_rules_for_user(
                    sync_config.user
                )
        else:
            (
                global_account_data,
                account_data_by_room,
            ) = await self.store.get_account_data_for_user(sync_config.user.to_string())

            global_account_data["m.push_rules"] = await self.push_rules_for_user(
                sync_config.user
            )

        account_data_for_user = await sync_config.filter_collection.filter_account_data(
            [
                {"type": account_data_type, "content": content}
                for account_data_type, content in global_account_data.items()
            ]
        )

        sync_result_builder.account_data = account_data_for_user

        return account_data_by_room

    async def _generate_sync_entry_for_presence(
        self,
        sync_result_builder: "SyncResultBuilder",
        newly_joined_rooms: AbstractSet[str],
        newly_joined_or_invited_users: AbstractSet[str],
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

        presence_source = self.event_sources.sources.presence

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
            StreamKeyType.PRESENCE, presence_key
        )

        extra_users_ids = set(newly_joined_or_invited_users)
        for room_id in newly_joined_rooms:
            users = await self.store.get_users_in_room(room_id)
            extra_users_ids.update(users)
        extra_users_ids.discard(user.to_string())

        if extra_users_ids:
            states = await self.presence_handler.get_states(extra_users_ids)
            presence.extend(states)

            # Deduplicate the presence entries so that there's at most one per user
            presence = list({p.user_id: p for p in presence}.values())

        presence = await sync_config.filter_collection.filter_presence(presence)

        sync_result_builder.presence = presence

    async def _generate_sync_entry_for_rooms(
        self,
        sync_result_builder: "SyncResultBuilder",
        account_data_by_room: Dict[str, Dict[str, JsonDict]],
    ) -> Tuple[AbstractSet[str], AbstractSet[str], AbstractSet[str], AbstractSet[str]]:
        """Generates the rooms portion of the sync response. Populates the
        `sync_result_builder` with the result.

        In the response that reaches the client, rooms are divided into four categories:
        `invite`, `join`, `knock`, `leave`. These aren't the same as the four sets of
        room ids returned by this function.

        Args:
            sync_result_builder
            account_data_by_room: Dictionary of per room account data

        Returns:
            Returns a 4-tuple describing rooms the user has joined or left, and users who've
            joined or left rooms any rooms the user is in. This gets used later in
            `_generate_sync_entry_for_device_list`.

            Its entries are:
            - newly_joined_rooms
            - newly_joined_or_invited_or_knocked_users
            - newly_left_rooms
            - newly_left_users
        """
        since_token = sync_result_builder.since_token

        # 1. Start by fetching all ephemeral events in rooms we've joined (if required).
        user_id = sync_result_builder.sync_config.user.to_string()
        block_all_room_ephemeral = (
            since_token is None
            and sync_result_builder.sync_config.filter_collection.blocks_all_room_ephemeral()
        )

        if block_all_room_ephemeral:
            ephemeral_by_room: Dict[str, List[JsonDict]] = {}
        else:
            now_token, ephemeral_by_room = await self.ephemeral_by_room(
                sync_result_builder,
                now_token=sync_result_builder.now_token,
                since_token=sync_result_builder.since_token,
            )
            sync_result_builder.now_token = now_token

        # 2. We check up front if anything has changed, if it hasn't then there is
        # no point in going further.
        if not sync_result_builder.full_state:
            if since_token and not ephemeral_by_room and not account_data_by_room:
                have_changed = await self._have_rooms_changed(sync_result_builder)
                log_kv({"rooms_have_changed": have_changed})
                if not have_changed:
                    tags_by_room = await self.store.get_updated_tags(
                        user_id, since_token.account_data_key
                    )
                    if not tags_by_room:
                        logger.debug("no-oping sync")
                        return set(), set(), set(), set()

        # 3. Work out which rooms need reporting in the sync response.
        ignored_users = await self.store.ignored_users(user_id)
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

        log_kv({"rooms_changed": len(room_changes.room_entries)})

        room_entries = room_changes.room_entries
        invited = room_changes.invited
        knocked = room_changes.knocked
        newly_joined_rooms = room_changes.newly_joined_rooms
        newly_left_rooms = room_changes.newly_left_rooms

        # 4. We need to apply further processing to `room_entries` (rooms considered
        # joined or archived).
        async def handle_room_entries(room_entry: "RoomSyncResultBuilder") -> None:
            logger.debug("Generating room entry for %s", room_entry.room_id)
            await self._generate_room_entry(
                sync_result_builder,
                room_entry,
                ephemeral=ephemeral_by_room.get(room_entry.room_id, []),
                tags=tags_by_room.get(room_entry.room_id),
                account_data=account_data_by_room.get(room_entry.room_id, {}),
                always_include=sync_result_builder.full_state,
            )
            logger.debug("Generated room entry for %s", room_entry.room_id)

        with start_active_span("sync.generate_room_entries"):
            await concurrently_execute(handle_room_entries, room_entries, 10)

        sync_result_builder.invited.extend(invited)
        sync_result_builder.knocked.extend(knocked)

        # 5. Work out which users have joined or left rooms we're in. We use this
        # to build the device_list part of the sync response in
        # `_generate_sync_entry_for_device_list`.
        (
            newly_joined_or_invited_or_knocked_users,
            newly_left_users,
        ) = sync_result_builder.calculate_user_changes()

        return (
            set(newly_joined_rooms),
            newly_joined_or_invited_or_knocked_users,
            set(newly_left_rooms),
            newly_left_users,
        )

    async def _have_rooms_changed(
        self, sync_result_builder: "SyncResultBuilder"
    ) -> bool:
        """Returns whether there may be any new events that should be sent down
        the sync. Returns True if there are.

        Does not modify the `sync_result_builder`.
        """
        since_token = sync_result_builder.since_token
        membership_change_events = sync_result_builder.membership_change_events

        assert since_token

        if membership_change_events:
            return True

        stream_id = since_token.room_key.stream
        for room_id in sync_result_builder.joined_room_ids:
            if self.store.has_room_changed_since(room_id, stream_id):
                return True
        return False

    async def _get_rooms_changed(
        self,
        sync_result_builder: "SyncResultBuilder",
        ignored_users: FrozenSet[str],
    ) -> _RoomChanges:
        """Determine the changes in rooms to report to the user.

        This function is a first pass at generating the rooms part of the sync response.
        It determines which rooms have changed during the sync period, and categorises
        them into four buckets: "knock", "invite", "join" and "leave". It also excludes
        from that list any room that appears in the list of rooms to exclude from sync
        results in the server configuration.

        1. Finds all membership changes for the user in the sync period (from
           `since_token` up to `now_token`).
        2. Uses those to place the room in one of the four categories above.
        3. Builds a `_RoomChanges` struct to record this, and return that struct.

        For rooms classified as "knock", "invite" or "leave", we just need to report
        a single membership event in the eventual /sync response. For "join" we need
        to fetch additional non-membership events, e.g. messages in the room. That is
        more complicated, so instead we report an intermediary `RoomSyncResultBuilder`
        struct, and leave the additional work to `_generate_room_entry`.

        The sync_result_builder is not modified by this function.
        """
        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token
        now_token = sync_result_builder.now_token
        sync_config = sync_result_builder.sync_config
        membership_change_events = sync_result_builder.membership_change_events

        assert since_token

        mem_change_events_by_room_id: Dict[str, List[EventBase]] = {}
        for event in membership_change_events:
            mem_change_events_by_room_id.setdefault(event.room_id, []).append(event)

        newly_joined_rooms: List[str] = []
        newly_left_rooms: List[str] = []
        room_entries: List[RoomSyncResultBuilder] = []
        invited: List[InvitedSyncResult] = []
        knocked: List[KnockedSyncResult] = []
        for room_id, events in mem_change_events_by_room_id.items():
            # The body of this loop will add this room to at least one of the five lists
            # above. Things get messy if you've e.g. joined, left, joined then left the
            # room all in the same sync period.
            logger.debug(
                "Membership changes in %s: [%s]",
                room_id,
                ", ".join("%s (%s)" % (e.event_id, e.membership) for e in events),
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
                old_state_ids = await self.get_state_at(
                    room_id,
                    since_token,
                    state_filter=StateFilter.from_types([(EventTypes.Member, user_id)]),
                )
                old_mem_ev_id = old_state_ids.get((EventTypes.Member, user_id), None)
                old_mem_ev = None
                if old_mem_ev_id:
                    old_mem_ev = await self.store.get_event(
                        old_mem_ev_id, allow_none=True
                    )

                if not old_mem_ev or old_mem_ev.membership != Membership.JOIN:
                    newly_joined_rooms.append(room_id)

            # If user is in the room then we don't need to do the invite/leave checks
            if room_id in sync_result_builder.joined_room_ids:
                continue

            if not non_joins:
                continue
            last_non_join = non_joins[-1]

            # Check if we have left the room. This can either be because we were
            # joined before *or* that we since joined and then left.
            if events[-1].membership != Membership.JOIN:
                if has_join:
                    newly_left_rooms.append(room_id)
                else:
                    if not old_state_ids:
                        old_state_ids = await self.get_state_at(
                            room_id,
                            since_token,
                            state_filter=StateFilter.from_types(
                                [(EventTypes.Member, user_id)]
                            ),
                        )
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
            should_invite = last_non_join.membership == Membership.INVITE
            if should_invite:
                if last_non_join.sender not in ignored_users:
                    invite_room_sync = InvitedSyncResult(room_id, invite=last_non_join)
                    if invite_room_sync:
                        invited.append(invite_room_sync)

            # Only bother if our latest membership in the room is knock (and we haven't
            # been accepted/rejected in the meantime).
            should_knock = last_non_join.membership == Membership.KNOCK
            if should_knock:
                knock_room_sync = KnockedSyncResult(room_id, knock=last_non_join)
                if knock_room_sync:
                    knocked.append(knock_room_sync)

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
                    StreamKeyType.ROOM, leave_position.to_room_stream_token()
                )

                # If this is an out of band message, like a remote invite
                # rejection, we include it in the recents batch. Otherwise, we
                # let _load_filtered_recents handle fetching the correct
                # batches.
                #
                # This is all screaming out for a refactor, as the logic here is
                # subtle and the moving parts numerous.
                if leave_event.internal_metadata.is_out_of_band_membership():
                    batch_events: Optional[List[EventBase]] = [leave_event]
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
                        out_of_band=leave_event.internal_metadata.is_out_of_band_membership(),
                    )
                )

        timeline_limit = sync_config.filter_collection.timeline_limit()

        # Get all events since the `from_key` in rooms we're currently joined to.
        # If there are too many, we get the most recent events only. This leaves
        # a "gap" in the timeline, as described by the spec for /sync.
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

                prev_batch_token = now_token.copy_and_replace(
                    StreamKeyType.ROOM, start_key
                )

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

            room_entries.append(entry)

        return _RoomChanges(
            room_entries,
            invited,
            knocked,
            newly_joined_rooms,
            newly_left_rooms,
        )

    async def _get_all_rooms(
        self,
        sync_result_builder: "SyncResultBuilder",
        ignored_users: FrozenSet[str],
    ) -> _RoomChanges:
        """Returns entries for all rooms for the user.

        Like `_get_rooms_changed`, but assumes the `since_token` is `None`.

        This function does not modify the sync_result_builder.

        Args:
            sync_result_builder
            ignored_users: Set of users ignored by user.
            ignored_rooms: List of rooms to ignore.
        """

        user_id = sync_result_builder.sync_config.user.to_string()
        since_token = sync_result_builder.since_token
        now_token = sync_result_builder.now_token
        sync_config = sync_result_builder.sync_config

        room_list = await self.store.get_rooms_for_local_user_where_membership_is(
            user_id=user_id,
            membership_list=Membership.LIST,
            excluded_rooms=self.rooms_to_exclude,
        )

        room_entries = []
        invited = []
        knocked = []

        for event in room_list:
            if event.room_version_id not in KNOWN_ROOM_VERSIONS:
                continue

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
            elif event.membership == Membership.KNOCK:
                knock = await self.store.get_event(event.event_id)
                knocked.append(KnockedSyncResult(room_id=event.room_id, knock=knock))
            elif event.membership in (Membership.LEAVE, Membership.BAN):
                # Always send down rooms we were banned from or kicked from.
                if not sync_config.filter_collection.include_leave:
                    if event.membership == Membership.LEAVE:
                        if user_id == event.sender:
                            continue

                leave_token = now_token.copy_and_replace(
                    StreamKeyType.ROOM, RoomStreamToken(None, event.stream_ordering)
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

        return _RoomChanges(room_entries, invited, knocked, [], [])

    async def _generate_room_entry(
        self,
        sync_result_builder: "SyncResultBuilder",
        room_builder: "RoomSyncResultBuilder",
        ephemeral: List[JsonDict],
        tags: Optional[Dict[str, Dict[str, Any]]],
        account_data: Dict[str, JsonDict],
        always_include: bool = False,
    ) -> None:
        """Populates the `joined` and `archived` section of `sync_result_builder`
        based on the `room_builder`.

        Ideally, we want to report all events whose stream ordering `s` lies in the
        range `since_token < s <= now_token`, where the two tokens are read from the
        sync_result_builder.

        If there are too many events in that range to report, things get complicated.
        In this situation we return a truncated list of the most recent events, and
        indicate in the response that there is a "gap" of omitted events. Lots of this
        is handled in `_load_filtered_recents`, but some of is handled in this method.

        Additionally:
        - we include a "state_delta", to describe the changes in state over the gap,
        - we include all membership events applying to the user making the request,
          even those in the gap.

        See the spec for the rationale:
            https://spec.matrix.org/v1.1/client-server-api/#syncing

        Args:
            sync_result_builder
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

        with start_active_span("sync.generate_room_entry"):
            set_tag("room_id", room_id)
            log_kv({"events": len(events or ())})

            log_kv(
                {
                    "since_token": since_token,
                    "upto_token": upto_token,
                }
            )

            batch = await self._load_filtered_recents(
                room_id,
                sync_config,
                now_token=upto_token,
                since_token=since_token,
                potential_recents=events,
                newly_joined_room=newly_joined,
            )
            log_kv(
                {
                    "batch_events": len(batch.events),
                    "prev_batch": batch.prev_batch,
                    "batch_limited": batch.limited,
                }
            )

            # Note: `batch` can be both empty and limited here in the case where
            # `_load_filtered_recents` can't find any events the user should see
            # (e.g. due to having ignored the sender of the last 50 events).

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
                account_data_events.append(
                    {"type": account_data_type, "content": content}
                )

            account_data_events = (
                await sync_config.filter_collection.filter_room_account_data(
                    account_data_events
                )
            )

            ephemeral = await sync_config.filter_collection.filter_room_ephemeral(
                ephemeral
            )

            if not (
                always_include
                or batch
                or account_data_events
                or ephemeral
                or full_state
            ):
                return

            if not room_builder.out_of_band:
                state = await self.compute_state_delta(
                    room_id,
                    batch,
                    sync_config,
                    since_token,
                    now_token,
                    full_state=full_state,
                )
            else:
                # An out of band room won't have any state changes.
                state = {}

            summary: Optional[JsonDict] = {}

            # we include a summary in room responses when we're lazy loading
            # members (as the client otherwise doesn't have enough info to form
            # the name itself).
            if (
                not room_builder.out_of_band
                and sync_config.filter_collection.lazy_load_members()
                and (
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
                )
            ):
                summary = await self.compute_summary(
                    room_id, sync_config, batch, state, now_token
                )

            if room_builder.rtype == "joined":
                unread_notifications: Dict[str, int] = {}
                room_sync = JoinedSyncResult(
                    room_id=room_id,
                    timeline=batch,
                    state=state,
                    ephemeral=ephemeral,
                    account_data=account_data_events,
                    unread_notifications=unread_notifications,
                    unread_thread_notifications={},
                    summary=summary,
                    unread_count=0,
                )

                if room_sync or always_include:
                    notifs = await self.unread_notifs_for_room_id(room_id, sync_config)

                    # Notifications for the main timeline.
                    notify_count = notifs.main_timeline.notify_count
                    highlight_count = notifs.main_timeline.highlight_count
                    unread_count = notifs.main_timeline.unread_count

                    # Check the sync configuration.
                    if sync_config.filter_collection.unread_thread_notifications():
                        # And add info for each thread.
                        room_sync.unread_thread_notifications = {
                            thread_id: {
                                "notification_count": thread_notifs.notify_count,
                                "highlight_count": thread_notifs.highlight_count,
                            }
                            for thread_id, thread_notifs in notifs.threads.items()
                            if thread_id is not None
                        }

                    else:
                        # Combine the unread counts for all threads and main timeline.
                        for thread_notifs in notifs.threads.values():
                            notify_count += thread_notifs.notify_count
                            highlight_count += thread_notifs.highlight_count
                            unread_count += thread_notifs.unread_count

                    unread_notifications["notification_count"] = notify_count
                    unread_notifications["highlight_count"] = highlight_count
                    room_sync.unread_count = unread_count

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
    timeline_end: StateMap[str],
    previous_timeline_end: StateMap[str],
    lazy_load_members: bool,
) -> StateMap[str]:
    """Works out what state to include in a sync response.

    Args:
        timeline_contains: state in the timeline
        timeline_start: state at the start of the timeline
        timeline_end: state at the end of the timeline
        previous_timeline_end: state at the end of the previous sync (or empty dict
            if this is an initial sync)
        lazy_load_members: whether to return members from timeline_start
            or not.  assumes that timeline_start has already been filtered to
            include only the members the client needs to know about.
    """
    event_id_to_state_key = {
        event_id: state_key
        for state_key, event_id in itertools.chain(
            timeline_contains.items(),
            timeline_start.items(),
            timeline_end.items(),
            previous_timeline_end.items(),
        )
    }

    timeline_end_ids = set(timeline_end.values())
    timeline_start_ids = set(timeline_start.values())
    previous_timeline_end_ids = set(previous_timeline_end.values())
    timeline_contains_ids = set(timeline_contains.values())

    # If we are lazyloading room members, we explicitly add the membership events
    # for the senders in the timeline into the state block returned by /sync,
    # as we may not have sent them to the client before.  We find these membership
    # events by filtering them out of timeline_start, which has already been filtered
    # to only include membership events for the senders in the timeline.
    # In practice, we can do this by removing them from the previous_timeline_end_ids
    # list, which is the list of relevant state we know we have already sent to the
    # client.
    # see https://github.com/matrix-org/synapse/pull/2970/files/efcdacad7d1b7f52f879179701c7e0d9b763511f#r204732809

    if lazy_load_members:
        previous_timeline_end_ids.difference_update(
            e for t, e in timeline_start.items() if t[0] == EventTypes.Member
        )

    state_ids = (
        (timeline_end_ids | timeline_start_ids)
        - previous_timeline_end_ids
        - timeline_contains_ids
    )

    return {event_id_to_state_key[e]: e for e in state_ids}


@attr.s(slots=True, auto_attribs=True)
class SyncResultBuilder:
    """Used to help build up a new SyncResult for a user

    Attributes:
        sync_config
        full_state: The full_state flag as specified by user
        since_token: The token supplied by user, or None.
        now_token: The token to sync up to.
        joined_room_ids: List of rooms the user is joined to

        # The following mirror the fields in a sync response
        presence
        account_data
        joined
        invited
        knocked
        archived
        to_device
    """

    sync_config: SyncConfig
    full_state: bool
    since_token: Optional[StreamToken]
    now_token: StreamToken
    joined_room_ids: FrozenSet[str]
    membership_change_events: List[EventBase]

    presence: List[UserPresenceState] = attr.Factory(list)
    account_data: List[JsonDict] = attr.Factory(list)
    joined: List[JoinedSyncResult] = attr.Factory(list)
    invited: List[InvitedSyncResult] = attr.Factory(list)
    knocked: List[KnockedSyncResult] = attr.Factory(list)
    archived: List[ArchivedSyncResult] = attr.Factory(list)
    to_device: List[JsonDict] = attr.Factory(list)

    def calculate_user_changes(self) -> Tuple[AbstractSet[str], AbstractSet[str]]:
        """Work out which other users have joined or left rooms we are joined to.

        This data only is only useful for an incremental sync.

        The SyncResultBuilder is not modified by this function.
        """
        newly_joined_or_invited_or_knocked_users = set()
        newly_left_users = set()
        if self.since_token:
            for joined_sync in self.joined:
                it = itertools.chain(
                    joined_sync.timeline.events, joined_sync.state.values()
                )
                for event in it:
                    if event.type == EventTypes.Member:
                        if (
                            event.membership == Membership.JOIN
                            or event.membership == Membership.INVITE
                            or event.membership == Membership.KNOCK
                        ):
                            newly_joined_or_invited_or_knocked_users.add(
                                event.state_key
                            )
                        else:
                            prev_content = event.unsigned.get("prev_content", {})
                            prev_membership = prev_content.get("membership", None)
                            if prev_membership == Membership.JOIN:
                                newly_left_users.add(event.state_key)

        newly_left_users -= newly_joined_or_invited_or_knocked_users
        return newly_joined_or_invited_or_knocked_users, newly_left_users


@attr.s(slots=True, auto_attribs=True)
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
        out_of_band: whether the events in the room are "out of band" events
            and the server isn't in the room.
    """

    room_id: str
    rtype: str
    events: Optional[List[EventBase]]
    newly_joined: bool
    full_state: bool
    since_token: Optional[StreamToken]
    upto_token: StreamToken

    out_of_band: bool = False
