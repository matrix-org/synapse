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
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from twisted.python.failure import Failure

from synapse.api.constants import Direction, EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.api.filtering import Filter
from synapse.events.utils import SerializeEventConfig
from synapse.handlers.room import DeleteStatus, ShutdownRoomParams, ShutdownRoomResponse
from synapse.logging.opentracing import trace
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.rest.admin._base import assert_user_is_admin
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, Requester, StreamKeyType
from synapse.types.state import StateFilter
from synapse.util.async_helpers import ReadWriteLock
from synapse.util.stringutils import random_string
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)

# How many single event gaps we tolerate returning in a `/messages` response before we
# backfill and try to fill in the history. This is an arbitrarily picked number so feel
# free to tune it in the future.
BACKFILL_BECAUSE_TOO_MANY_GAPS_THRESHOLD = 3


class PaginationHandler:
    """Handles pagination and purge history requests.

    These are in the same handler due to the fact we need to block clients
    paginating during a purge.
    """

    # when to remove a completed deletion/purge from the results map
    CLEAR_PURGE_AFTER_MS = 1000 * 3600 * 24  # 24 hours

    # how often to run the purge rooms loop
    PURGE_ROOMS_INTERVAL_MS = 1000 * 3600  # 1 hour

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
        self._purge_retention_period = hs.config.server.purge_retention_period
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

        if self._is_master:
            self.clock.looping_call(
                run_as_background_process,
                PaginationHandler.PURGE_ROOMS_INTERVAL_MS,
                "purge_rooms",
                self.purge_rooms,
            )

    async def purge_rooms(self) -> None:
        """This takes care of restoring unfinished purge/shutdown rooms from the DB.
        It also takes care to launch scheduled ones, like rooms that has been fully
        forgotten.

        It should be run regularly.
        """
        rooms_to_delete = await self.store.get_rooms_to_delete()
        for r in rooms_to_delete:
            room_id = r["room_id"]
            delete_id = r["delete_id"]
            status = r["status"]
            action = r["action"]
            timestamp = r["timestamp"]

            if (
                status == DeleteStatus.STATUS_COMPLETE
                or status == DeleteStatus.STATUS_FAILED
            ):
                # remove the delete from the list 24 hours after it completes or fails
                ms_since_completed = self.clock.time_msec() - timestamp
                if ms_since_completed >= PaginationHandler.CLEAR_PURGE_AFTER_MS:
                    await self.store.delete_room_to_delete(room_id, delete_id)

                continue

            if room_id in self._purges_in_progress_by_room:
                # a delete background task is already running (or has run)
                # for this room id, let's ignore it for now
                continue

            # If the database says we were last in the middle of shutting down the room,
            # let's continue the shutdown process.
            shutdown_response = None
            if (
                action == DeleteStatus.ACTION_SHUTDOWN
                and status == DeleteStatus.STATUS_SHUTTING_DOWN
            ):
                shutdown_params = json.loads(r["params"])
                if r["response"]:
                    shutdown_response = json.loads(r["response"])
                await self._shutdown_and_purge_room(
                    room_id,
                    delete_id,
                    shutdown_params=shutdown_params,
                    shutdown_response=shutdown_response,
                )
                continue

            # If the database says we were last in the middle of purging the room,
            # let's continue the purge process.
            if status == DeleteStatus.STATUS_PURGING:
                purge_now = True
            # Or if we're at or past the scheduled purge time, let's start that one as well
            elif status == DeleteStatus.STATUS_SCHEDULED and (
                timestamp is None or self.clock.time_msec() >= timestamp
            ):
                purge_now = True

            # TODO 2 stages purge, keep memberships for a while so we don't "break" sync
            if purge_now:
                params = {}
                if r["params"]:
                    params = json.loads(r["params"])

                if action == DeleteStatus.ACTION_PURGE_HISTORY:
                    if "token" in params:
                        await self._purge_history(
                            delete_id,
                            room_id,
                            params["token"],
                            params.get("delete_local_events", False),
                            True,
                        )
                elif action == DeleteStatus.ACTION_PURGE:
                    await self.purge_room(
                        room_id,
                        delete_id,
                        params.get("force", False),
                        shutdown_response=shutdown_response,
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
            "[purge] Running purge job for %s < max_lifetime <= %s (include NULLs = %s)",
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

            if room_id in self._purges_in_progress_by_room:
                logger.warning(
                    "[purge] not purging room %s as there's an ongoing purge running"
                    " for this room",
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

            purge_id = random_string(16)

            logger.info(
                "Starting purging events in room %s (purge_id %s)" % (room_id, purge_id)
            )

            # We want to purge everything, including local events, and to run the purge in
            # the background so that it's not blocking any other operation apart from
            # other purges in the same room.
            run_as_background_process(
                "_purge_history",
                self._purge_history,
                purge_id,
                room_id,
                token,
                True,
                False,
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
        if room_id in self._purges_in_progress_by_room:
            raise SynapseError(
                400, "History purge already in progress for %s" % (room_id,)
            )

        purge_id = random_string(16)

        # we log the purge_id here so that it can be tied back to the
        # request id in the log lines.
        logger.info("[purge] starting purge_id %s", purge_id)

        await self.store.upsert_room_to_delete(
            room_id,
            purge_id,
            DeleteStatus.ACTION_PURGE_HISTORY,
            DeleteStatus.STATUS_PURGING,
            params=json.dumps(
                {"token": token, "delete_local_events": delete_local_events}
            ),
        )

        run_as_background_process(
            "purge_history",
            self._purge_history,
            purge_id,
            room_id,
            token,
            delete_local_events,
            True,
        )
        return purge_id

    async def _purge_history(
        self,
        purge_id: str,
        room_id: str,
        token: str,
        delete_local_events: bool,
        update_rooms_to_delete_table: bool,
    ) -> None:
        """Carry out a history purge on a room.

        Args:
            purge_id: The ID for this purge.
            room_id: The room to purge from
            token: topological token to delete events before
            delete_local_events: True to delete local events as well as remote ones
            update_rooms_to_delete_table: True if we don't want to update/persist this
                purge history action to the DB to be restorable. Used with the retention
                functionality since we don't need to explicitly restore those, they
                will be relaunch by the retention logic.
        """
        self._purges_in_progress_by_room.add(room_id)
        try:
            async with self.pagination_lock.write(room_id):
                await self._storage_controllers.purge_events.purge_history(
                    room_id, token, delete_local_events
                )
            logger.info("[purge] complete")
            if update_rooms_to_delete_table:
                await self.store.upsert_room_to_delete(
                    room_id,
                    purge_id,
                    DeleteStatus.ACTION_PURGE_HISTORY,
                    DeleteStatus.STATUS_COMPLETE,
                    timestamp=self.clock.time_msec(),
                )
        except Exception:
            f = Failure()
            logger.error(
                "[purge] failed", exc_info=(f.type, f.value, f.getTracebackObject())
            )
            if update_rooms_to_delete_table:
                await self.store.upsert_room_to_delete(
                    room_id,
                    purge_id,
                    DeleteStatus.ACTION_PURGE_HISTORY,
                    DeleteStatus.STATUS_FAILED,
                    error=f.getErrorMessage(),
                    timestamp=self.clock.time_msec(),
                )
        finally:
            self._purges_in_progress_by_room.discard(room_id)

            if update_rooms_to_delete_table:
                # remove the purge from the list 24 hours after it completes
                async def clear_purge() -> None:
                    await self.store.delete_room_to_delete(room_id, purge_id)

                self.hs.get_reactor().callLater(
                    PaginationHandler.CLEAR_PURGE_AFTER_MS / 1000, clear_purge
                )

    @staticmethod
    def _convert_to_delete_status(res: Dict[str, Any]) -> DeleteStatus:
        status = DeleteStatus()
        status.delete_id = res["delete_id"]
        status.action = res["action"]
        status.status = res["status"]
        if "error" in res:
            status.error = res["error"]

        if status.action == DeleteStatus.ACTION_SHUTDOWN and res["response"]:
            status.shutdown_room = json.loads(res["response"])

        return status

    async def get_delete_status(self, delete_id: str) -> Optional[DeleteStatus]:
        """Get the current status of an active deleting

        Args:
            delete_id: delete_id returned by start_shutdown_and_purge_room
                or start_purge_history.
        """
        res = await self.store.get_room_to_delete(delete_id)
        if res:
            return PaginationHandler._convert_to_delete_status(res)
        return None

    async def get_delete_statuses_by_room(self, room_id: str) -> List[DeleteStatus]:
        """Get all active delete statuses by room

        Args:
            room_id: room_id that is deleted
        """
        res = await self.store.get_rooms_to_delete(room_id)
        return [PaginationHandler._convert_to_delete_status(r) for r in res]

    async def purge_room(
        self,
        room_id: str,
        delete_id: str,
        force: bool = False,
        shutdown_response: Optional[ShutdownRoomResponse] = None,
    ) -> None:
        """Purge the given room from the database.

        Args:
            room_id: room to be purged
            delete_id: the delete ID for this purge
            force: set true to skip checking for joined users.
            shutdown_response: optional response coming from the shutdown phase
        """
        logger.info("starting purge room_id=%s force=%s", room_id, force)

        action = DeleteStatus.ACTION_PURGE
        if shutdown_response:
            action = DeleteStatus.ACTION_SHUTDOWN

        async with self.pagination_lock.write(room_id):
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

            await self.store.upsert_room_to_delete(
                room_id,
                delete_id,
                action,
                DeleteStatus.STATUS_PURGING,
                response=json.dumps(shutdown_response),
            )

            await self._storage_controllers.purge_events.purge_room(room_id)

            await self.store.upsert_room_to_delete(
                room_id,
                delete_id,
                action,
                DeleteStatus.STATUS_COMPLETE,
                timestamp=self.clock.time_msec(),
                response=json.dumps(shutdown_response),
            )

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

        async with self.pagination_lock.read(room_id):
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
                    did_backfill = (
                        await self.hs.get_federation_handler().maybe_backfill(
                            room_id,
                            curr_topo,
                            limit=pagin_config.limit,
                        )
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
                self._event_serializer.serialize_events(
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
            chunk["state"] = self._event_serializer.serialize_events(
                state, time_now, config=serialize_options
            )

        return chunk

    async def _shutdown_and_purge_room(
        self,
        room_id: str,
        delete_id: str,
        shutdown_params: ShutdownRoomParams,
        shutdown_response: Optional[ShutdownRoomResponse] = None,
    ) -> None:
        """
        Shuts down and purges a room.

        See `RoomShutdownHandler.shutdown_room` for details of creation of the new room

        Args:
            delete_id: The ID for this delete.
            room_id: The ID of the room to shut down.
            shutdown_params: parameters for the shutdown, cf `RoomShutdownHandler.ShutdownRoomParams`
            shutdown_response: current status of the shutdown, if it was interrupted

        Keeps track of the `DeleteStatus` (and `ShutdownRoomResponse`) in `self._delete_by_id` and persisted in DB
        """

        self._purges_in_progress_by_room.add(room_id)
        try:
            shutdown_response = await self._room_shutdown_handler.shutdown_room(
                room_id=room_id,
                delete_id=delete_id,
                shutdown_params=shutdown_params,
                shutdown_response=shutdown_response,
            )

            if shutdown_params["purge"]:
                await self.purge_room(
                    room_id,
                    delete_id,
                    shutdown_params["force_purge"],
                    shutdown_response=shutdown_response,
                )

            await self.store.upsert_room_to_delete(
                room_id,
                delete_id,
                DeleteStatus.ACTION_SHUTDOWN,
                DeleteStatus.STATUS_COMPLETE,
                timestamp=self.clock.time_msec(),
                response=json.dumps(shutdown_response),
            )
        except Exception:
            f = Failure()
            logger.error(
                "failed",
                exc_info=(f.type, f.value, f.getTracebackObject()),
            )
            await self.store.upsert_room_to_delete(
                room_id,
                delete_id,
                DeleteStatus.ACTION_SHUTDOWN,
                DeleteStatus.STATUS_FAILED,
                timestamp=self.clock.time_msec(),
                error=f.getErrorMessage(),
            )
        finally:
            self._purges_in_progress_by_room.discard(room_id)

    def start_shutdown_and_purge_room(
        self,
        room_id: str,
        shutdown_params: ShutdownRoomParams,
    ) -> str:
        """Start off shut down and purge on a room.

        Args:
            room_id: The ID of the room to shut down.
            shutdown_params: parameters for the shutdown, cf `RoomShutdownHandler.ShutdownRoomParams`

        Returns:
            unique ID for this delete transaction.
        """
        if room_id in self._purges_in_progress_by_room:
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

        delete_id = random_string(16)

        # we log the delete_id here so that it can be tied back to the
        # request id in the log lines.
        logger.info(
            "starting shutdown room_id %s with delete_id %s",
            room_id,
            delete_id,
        )

        run_as_background_process(
            "shutdown_and_purge_room",
            self._shutdown_and_purge_room,
            room_id,
            delete_id,
            shutdown_params,
        )
        return delete_id
