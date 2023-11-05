# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 - 2018 New Vector Ltd
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
from typing import TYPE_CHECKING, List, Optional, Set, Tuple, cast

from twisted.python.failure import Failure

from synapse.api.constants import Direction, EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.api.filtering import Filter
from synapse.events.utils import SerializeEventConfig
from synapse.handlers.room import ShutdownRoomParams, ShutdownRoomResponse
from synapse.handlers.worker_lock import NEW_EVENT_DURING_PURGE_LOCK_NAME
from synapse.logging.opentracing import trace
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.rest.admin._base import assert_user_is_admin
from synapse.streams.config import PaginationConfig
from synapse.types import (
    JsonDict,
    JsonMapping,
    Requester,
    ScheduledTask,
    StreamKeyType,
    TaskStatus,
)
from synapse.types.state import StateFilter
from synapse.util.async_helpers import ReadWriteLock
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)

# How many single event gaps we tolerate returning in a `/messages` response before we
# backfill and try to fill in the history. This is an arbitrarily picked number so feel
# free to tune it in the future.
BACKFILL_BECAUSE_TOO_MANY_GAPS_THRESHOLD = 3


# This is used to avoid purging a room several time at the same moment,
# and also paginating during a purge. Pagination can trigger backfill,
# which would create old events locally, and would potentially clash with the room delete.
PURGE_PAGINATION_LOCK_NAME = "purge_pagination_lock"


PURGE_HISTORY_ACTION_NAME = "purge_history"

PURGE_ROOM_ACTION_NAME = "purge_room"

SHUTDOWN_AND_PURGE_ROOM_ACTION_NAME = "shutdown_and_purge_room"


class PaginationHandler:
    """Handles pagination and purge history requests.

    These are in the same handler due to the fact we need to block clients
    paginating during a purge.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self._state_storage_controller = self._storage_controllers.state
        self.clock = hs.get_clock()
        self._server_name = hs.hostname
        self._room_shutdown_handler = hs.get_room_shutdown_handler()
        self._relations_handler = hs.get_relations_handler()
        self._worker_locks = hs.get_worker_locks_handler()
        self._task_scheduler = hs.get_task_scheduler()

        self.pagination_lock = ReadWriteLock()
        # IDs of rooms in which there currently an active purge *or delete* operation.
        self._purges_in_progress_by_room: Set[str] = set()
        self._event_serializer = hs.get_event_client_serializer()

        self._retention_default_max_lifetime = (
            hs.config.retention.retention_default_max_lifetime
        )

        self._retention_allowed_lifetime_min = (
            hs.config.retention.retention_allowed_lifetime_min
        )
        self._retention_allowed_lifetime_max = (
            hs.config.retention.retention_allowed_lifetime_max
        )
        self._forgotten_room_retention_period = (
            hs.config.server.forgotten_room_retention_period
        )
        self._is_master = hs.config.worker.worker_app is None

        if hs.config.retention.retention_enabled and self._is_master:
            # Run the purge jobs described in the configuration file.
            for job in hs.config.retention.retention_purge_jobs:
                logger.info("Setting up purge job with config: %s", job)

                self.clock.looping_call(
                    run_as_background_process,
                    job.interval,
                    "purge_history_for_rooms_in_range",
                    self.purge_history_for_rooms_in_range,
                    job.shortest_max_lifetime,
                    job.longest_max_lifetime,
                )

        self._task_scheduler.register_action(
            self._purge_history, PURGE_HISTORY_ACTION_NAME
        )
        self._task_scheduler.register_action(self._purge_room, PURGE_ROOM_ACTION_NAME)
        self._task_scheduler.register_action(
            self._shutdown_and_purge_room, SHUTDOWN_AND_PURGE_ROOM_ACTION_NAME
        )

    async def purge_history_for_rooms_in_range(
        self, min_ms: Optional[int], max_ms: Optional[int]
    ) -> None:
        """Purge outdated events from rooms within the given retention range.

        If a default retention policy is defined in the server's configuration and its
        'max_lifetime' is within this range, also targets rooms which don't have a
        retention policy.

        Args:
            min_ms: Duration in milliseconds that define the lower limit of
                the range to handle (exclusive). If None, it means that the range has no
                lower limit.
            max_ms: Duration in milliseconds that define the upper limit of
                the range to handle (inclusive). If None, it means that the range has no
                upper limit.
        """
        # We want the storage layer to include rooms with no retention policy in its
        # return value only if a default retention policy is defined in the server's
        # configuration and that policy's 'max_lifetime' is either lower (or equal) than
        # max_ms or higher than min_ms (or both).
        if self._retention_default_max_lifetime is not None:
            include_null = True

            if min_ms is not None and min_ms >= self._retention_default_max_lifetime:
                # The default max_lifetime is lower than (or equal to) min_ms.
                include_null = False

            if max_ms is not None and max_ms < self._retention_default_max_lifetime:
                # The default max_lifetime is higher than max_ms.
                include_null = False
        else:
            include_null = False

        logger.info(
            "[purge] Running retention purge job for %s < max_lifetime <= %s (include NULLs = %s)",
            min_ms,
            max_ms,
            include_null,
        )

        rooms = await self.store.get_rooms_for_retention_period_in_range(
            min_ms, max_ms, include_null
        )

        logger.debug("[purge] Rooms to purge: %s", rooms)

        for room_id, retention_policy in rooms.items():
            logger.info("[purge] Attempting to purge messages in room %s", room_id)

            if len(await self.get_delete_tasks_by_room(room_id, only_active=True)) > 0:
                logger.warning(
                    "[purge] not purging room %s for retention as there's an ongoing purge"
                    " running for this room",
                    room_id,
                )
                continue

            # If max_lifetime is None, it means that the room has no retention policy.
            # Given we only retrieve such rooms when there's a default retention policy
            # defined in the server's configuration, we can safely assume that's the
            # case and use it for this room.
            max_lifetime = (
                retention_policy.max_lifetime or self._retention_default_max_lifetime
            )

            # Cap the effective max_lifetime to be within the range allowed in the
            # config.
            # We do this in two steps:
            #   1. Make sure it's higher or equal to the minimum allowed value, and if
            #      it's not replace it with that value. This is because the server
            #      operator can be required to not delete information before a given
            #      time, e.g. to comply with freedom of information laws.
            #   2. Make sure the resulting value is lower or equal to the maximum allowed
            #      value, and if it's not replace it with that value. This is because the
            #      server operator can be required to delete any data after a specific
            #      amount of time.
            if self._retention_allowed_lifetime_min is not None:
                max_lifetime = max(self._retention_allowed_lifetime_min, max_lifetime)

            if self._retention_allowed_lifetime_max is not None:
                max_lifetime = min(max_lifetime, self._retention_allowed_lifetime_max)

            logger.debug("[purge] max_lifetime for room %s: %s", room_id, max_lifetime)

            # Figure out what token we should start purging at.
            ts = self.clock.time_msec() - max_lifetime

            stream_ordering = await self.store.find_first_stream_ordering_after_ts(ts)

            r = await self.store.get_room_event_before_stream_ordering(
                room_id,
                stream_ordering,
            )
            if not r:
                logger.warning(
                    "[purge] purging events not possible: No event found "
                    "(ts %i => stream_ordering %i)",
                    ts,
                    stream_ordering,
                )
                continue

            (stream, topo, _event_id) = r
            token = "t%d-%d" % (topo, stream)

            logger.info("Starting purging events in room %s", room_id)

            # We want to purge everything, including local events, and to run the purge in
            # the background so that it's not blocking any other operation apart from
            # other purges in the same room.
            run_as_background_process(
                PURGE_HISTORY_ACTION_NAME,
                self.purge_history,
                room_id,
                token,
                True,
            )

    async def start_purge_history(
        self, room_id: str, token: str, delete_local_events: bool = False
    ) -> str:
        """Start off a history purge on a room.

        Args:
            room_id: The room to purge from
            token: topological token to delete events before
            delete_local_events: True to delete local events as well as
                remote ones

        Returns:
            unique ID for this purge transaction.
        """
        purge_id = await self._task_scheduler.schedule_task(
            PURGE_HISTORY_ACTION_NAME,
            resource_id=room_id,
            params={"token": token, "delete_local_events": delete_local_events},
        )

        # we log the purge_id here so that it can be tied back to the
        # request id in the log lines.
        logger.info("[purge] starting purge_id %s", purge_id)

        return purge_id

    async def _purge_history(
        self,
        task: ScheduledTask,
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        """
        Scheduler action to purge some history of a room.
        """
        if (
            task.resource_id is None
            or task.params is None
            or "token" not in task.params
            or "delete_local_events" not in task.params
        ):
            return (
                TaskStatus.FAILED,
                None,
                "Not enough parameters passed to _purge_history",
            )
        err = await self.purge_history(
            task.resource_id,
            task.params["token"],
            task.params["delete_local_events"],
        )
        if err is not None:
            return TaskStatus.FAILED, None, err
        return TaskStatus.COMPLETE, None, None

    async def purge_history(
        self,
        room_id: str,
        token: str,
        delete_local_events: bool,
    ) -> Optional[str]:
        """Carry out a history purge on a room.

        Args:
            room_id: The room to purge from
            token: topological token to delete events before
            delete_local_events: True to delete local events as well as remote ones
        """
        try:
            async with self._worker_locks.acquire_read_write_lock(
                PURGE_PAGINATION_LOCK_NAME, room_id, write=True
            ):
                await self._storage_controllers.purge_events.purge_history(
                    room_id, token, delete_local_events
                )
            logger.info("[purge] complete")
            return None
        except Exception:
            f = Failure()
            logger.error(
                "[purge] failed", exc_info=(f.type, f.value, f.getTracebackObject())
            )
            return f.getErrorMessage()

    async def get_delete_task(self, delete_id: str) -> Optional[ScheduledTask]:
        """Get the current status of an active deleting

        Args:
            delete_id: delete_id returned by start_shutdown_and_purge_room
                or start_purge_history.
        """
        return await self._task_scheduler.get_task(delete_id)

    async def get_delete_tasks_by_room(
        self, room_id: str, only_active: Optional[bool] = False
    ) -> List[ScheduledTask]:
        """Get complete, failed or active delete tasks by room

        Args:
            room_id: room_id that is deleted
            only_active: if True, completed&failed tasks will be omitted
        """
        statuses = [TaskStatus.ACTIVE]
        if not only_active:
            statuses += [TaskStatus.COMPLETE, TaskStatus.FAILED]

        return await self._task_scheduler.get_tasks(
            actions=[PURGE_ROOM_ACTION_NAME, SHUTDOWN_AND_PURGE_ROOM_ACTION_NAME],
            resource_id=room_id,
            statuses=statuses,
        )

    async def _purge_room(
        self,
        task: ScheduledTask,
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        """
        Scheduler action to purge a room.
        """
        if not task.resource_id:
            raise Exception("No room id passed to purge_room task")
        params = task.params if task.params else {}
        await self.purge_room(task.resource_id, params.get("force", False))
        return TaskStatus.COMPLETE, None, None

    async def purge_room(
        self,
        room_id: str,
        force: bool,
    ) -> None:
        """Purge the given room from the database.

        Args:
            room_id: room to be purged
            force: set true to skip checking for joined users.
        """
        logger.info("starting purge room_id=%s force=%s", room_id, force)

        async with self._worker_locks.acquire_multi_read_write_lock(
            [
                (PURGE_PAGINATION_LOCK_NAME, room_id),
                (NEW_EVENT_DURING_PURGE_LOCK_NAME, room_id),
            ],
            write=True,
        ):
            # first check that we have no users in this room
            joined = await self.store.is_host_joined(room_id, self._server_name)
            if joined:
                if force:
                    logger.info(
                        "force-purging room %s with some local users still joined",
                        room_id,
                    )
                else:
                    raise SynapseError(400, "Users are still joined to this room")

            await self._storage_controllers.purge_events.purge_room(room_id)

        logger.info("purge complete for room_id %s", room_id)

    @trace
    async def get_messages(
        self,
        requester: Requester,
        room_id: str,
        pagin_config: PaginationConfig,
        as_client_event: bool = True,
        event_filter: Optional[Filter] = None,
        use_admin_priviledge: bool = False,
    ) -> JsonDict:
        """Get messages in a room.

        Args:
            requester: The user requesting messages.
            room_id: The room they want messages from.
            pagin_config: The pagination config rules to apply, if any.
            as_client_event: True to get events in client-server format.
            event_filter: Filter to apply to results or None
            use_admin_priviledge: if `True`, return all events, regardless
                of whether `user` has access to them. To be used **ONLY**
                from the admin API.

        Returns:
            Pagination API results
        """
        if use_admin_priviledge:
            await assert_user_is_admin(self.auth, requester)

        user_id = requester.user.to_string()

        if pagin_config.from_token:
            from_token = pagin_config.from_token
        elif pagin_config.direction == Direction.FORWARDS:
            from_token = (
                await self.hs.get_event_sources().get_start_token_for_pagination(
                    room_id
                )
            )
        else:
            from_token = (
                await self.hs.get_event_sources().get_current_token_for_pagination(
                    room_id
                )
            )
            # We expect `/messages` to use historic pagination tokens by default but
            # `/messages` should still works with live tokens when manually provided.
            assert from_token.room_key.topological is not None

        room_token = from_token.room_key

        (membership, member_event_id) = (None, None)
        if not use_admin_priviledge:
            (
                membership,
                member_event_id,
            ) = await self.auth.check_user_in_room_or_world_readable(
                room_id, requester, allow_departed_users=True
            )

        if pagin_config.direction == Direction.BACKWARDS:
            # if we're going backwards, we might need to backfill. This
            # requires that we have a topo token.
            if room_token.topological:
                curr_topo = room_token.topological
            else:
                curr_topo = await self.store.get_current_topological_token(
                    room_id, room_token.stream
                )

        # If they have left the room then clamp the token to be before
        # they left the room, to save the effort of loading from the
        # database.
        if (
            pagin_config.direction == Direction.BACKWARDS
            and not use_admin_priviledge
            and membership == Membership.LEAVE
        ):
            # This is only None if the room is world_readable, in which case
            # "Membership.JOIN" would have been returned and we should never hit
            # this branch.
            assert member_event_id

            leave_token = await self.store.get_topological_token_for_event(
                member_event_id
            )
            assert leave_token.topological is not None

            if leave_token.topological < curr_topo:
                from_token = from_token.copy_and_replace(
                    StreamKeyType.ROOM, leave_token
                )

        to_room_key = None
        if pagin_config.to_token:
            to_room_key = pagin_config.to_token.room_key

        # Initially fetch the events from the database. With any luck, we can return
        # these without blocking on backfill (handled below).
        events, next_key = await self.store.paginate_room_events(
            room_id=room_id,
            from_key=from_token.room_key,
            to_key=to_room_key,
            direction=pagin_config.direction,
            limit=pagin_config.limit,
            event_filter=event_filter,
        )

        if pagin_config.direction == Direction.BACKWARDS:
            # We use a `Set` because there can be multiple events at a given depth
            # and we only care about looking at the unique continum of depths to
            # find gaps.
            event_depths: Set[int] = {event.depth for event in events}
            sorted_event_depths = sorted(event_depths)

            # Inspect the depths of the returned events to see if there are any gaps
            found_big_gap = False
            number_of_gaps = 0
            previous_event_depth = (
                sorted_event_depths[0] if len(sorted_event_depths) > 0 else 0
            )
            for event_depth in sorted_event_depths:
                # We don't expect a negative depth but we'll just deal with it in
                # any case by taking the absolute value to get the true gap between
                # any two integers.
                depth_gap = abs(event_depth - previous_event_depth)
                # A `depth_gap` of 1 is a normal continuous chain to the next event
                # (1 <-- 2 <-- 3) so anything larger indicates a missing event (it's
                # also possible there is no event at a given depth but we can't ever
                # know that for sure)
                if depth_gap > 1:
                    number_of_gaps += 1

                # We only tolerate a small number single-event long gaps in the
                # returned events because those are most likely just events we've
                # failed to pull in the past. Anything longer than that is probably
                # a sign that we're missing a decent chunk of history and we should
                # try to backfill it.
                #
                # XXX: It's possible we could tolerate longer gaps if we checked
                # that a given events `prev_events` is one that has failed pull
                # attempts and we could just treat it like a dead branch of history
                # for now or at least something that we don't need the block the
                # client on to try pulling.
                #
                # XXX: If we had something like MSC3871 to indicate gaps in the
                # timeline to the client, we could also get away with any sized gap
                # and just have the client refetch the holes as they see fit.
                if depth_gap > 2:
                    found_big_gap = True
                    break
                previous_event_depth = event_depth

            # Backfill in the foreground if we found a big gap, have too many holes,
            # or we don't have enough events to fill the limit that the client asked
            # for.
            missing_too_many_events = (
                number_of_gaps > BACKFILL_BECAUSE_TOO_MANY_GAPS_THRESHOLD
            )
            not_enough_events_to_fill_response = len(events) < pagin_config.limit
            if (
                found_big_gap
                or missing_too_many_events
                or not_enough_events_to_fill_response
            ):
                did_backfill = await self.hs.get_federation_handler().maybe_backfill(
                    room_id,
                    curr_topo,
                    limit=pagin_config.limit,
                )

                # If we did backfill something, refetch the events from the database to
                # catch anything new that might have been added since we last fetched.
                if did_backfill:
                    events, next_key = await self.store.paginate_room_events(
                        room_id=room_id,
                        from_key=from_token.room_key,
                        to_key=to_room_key,
                        direction=pagin_config.direction,
                        limit=pagin_config.limit,
                        event_filter=event_filter,
                    )
            else:
                # Otherwise, we can backfill in the background for eventual
                # consistency's sake but we don't need to block the client waiting
                # for a costly federation call and processing.
                run_as_background_process(
                    "maybe_backfill_in_the_background",
                    self.hs.get_federation_handler().maybe_backfill,
                    room_id,
                    curr_topo,
                    limit=pagin_config.limit,
                )

        next_token = from_token.copy_and_replace(StreamKeyType.ROOM, next_key)

        # if no events are returned from pagination, that implies
        # we have reached the end of the available events.
        # In that case we do not return end, to tell the client
        # there is no need for further queries.
        if not events:
            return {
                "chunk": [],
                "start": await from_token.to_string(self.store),
            }

        if event_filter:
            events = await event_filter.filter(events)

        if not use_admin_priviledge:
            events = await filter_events_for_client(
                self._storage_controllers,
                user_id,
                events,
                is_peeking=(member_event_id is None),
            )

        # if after the filter applied there are no more events
        # return immediately - but there might be more in next_token batch
        if not events:
            return {
                "chunk": [],
                "start": await from_token.to_string(self.store),
                "end": await next_token.to_string(self.store),
            }

        state = None
        if event_filter and event_filter.lazy_load_members and len(events) > 0:
            # TODO: remove redundant members

            # FIXME: we also care about invite targets etc.
            state_filter = StateFilter.from_types(
                (EventTypes.Member, event.sender) for event in events
            )

            state_ids = await self._state_storage_controller.get_state_ids_for_event(
                events[0].event_id, state_filter=state_filter
            )

            if state_ids:
                state_dict = await self.store.get_events(list(state_ids.values()))
                state = state_dict.values()

        aggregations = await self._relations_handler.get_bundled_aggregations(
            events, user_id
        )

        time_now = self.clock.time_msec()

        serialize_options = SerializeEventConfig(
            as_client_event=as_client_event, requester=requester
        )

        chunk = {
            "chunk": (
                await self._event_serializer.serialize_events(
                    events,
                    time_now,
                    config=serialize_options,
                    bundle_aggregations=aggregations,
                )
            ),
            "start": await from_token.to_string(self.store),
            "end": await next_token.to_string(self.store),
        }

        if state:
            chunk["state"] = await self._event_serializer.serialize_events(
                state, time_now, config=serialize_options
            )

        return chunk

    async def _shutdown_and_purge_room(
        self,
        task: ScheduledTask,
    ) -> Tuple[TaskStatus, Optional[JsonMapping], Optional[str]]:
        """
        Scheduler action to shutdown and purge a room.
        """
        if task.resource_id is None or task.params is None:
            raise Exception(
                "No room id and/or no parameters passed to shutdown_and_purge_room task"
            )

        room_id = task.resource_id

        async def update_result(result: Optional[JsonMapping]) -> None:
            await self._task_scheduler.update_task(task.id, result=result)

        shutdown_result = (
            cast(ShutdownRoomResponse, task.result) if task.result else None
        )

        shutdown_result = await self._room_shutdown_handler.shutdown_room(
            room_id,
            cast(ShutdownRoomParams, task.params),
            shutdown_result,
            update_result,
        )

        if task.params.get("purge", False):
            await self.purge_room(
                room_id,
                task.params.get("force_purge", False),
            )

        return (TaskStatus.COMPLETE, shutdown_result, None)

    async def start_shutdown_and_purge_room(
        self,
        room_id: str,
        shutdown_params: ShutdownRoomParams,
    ) -> str:
        """Start off shut down and purge on a room.

        Args:
            room_id: The ID of the room to shut down.
            shutdown_params: parameters for the shutdown

        Returns:
            unique ID for this delete transaction.
        """
        if len(await self.get_delete_tasks_by_room(room_id, only_active=True)) > 0:
            raise SynapseError(400, "Purge already in progress for %s" % (room_id,))

        # This check is double to `RoomShutdownHandler.shutdown_room`
        # But here the requester get a direct response / error with HTTP request
        # and do not have to check the purge status
        new_room_user_id = shutdown_params["new_room_user_id"]
        if new_room_user_id is not None:
            if not self.hs.is_mine_id(new_room_user_id):
                raise SynapseError(
                    400, "User must be our own: %s" % (new_room_user_id,)
                )

        delete_id = await self._task_scheduler.schedule_task(
            SHUTDOWN_AND_PURGE_ROOM_ACTION_NAME,
            resource_id=room_id,
            params=shutdown_params,
        )

        # we log the delete_id here so that it can be tied back to the
        # request id in the log lines.
        logger.info(
            "starting shutdown room_id %s with delete_id %s",
            room_id,
            delete_id,
        )

        return delete_id
