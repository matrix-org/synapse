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
from typing import TYPE_CHECKING, Any, Collection, Dict, List, Optional, Set

import attr

from twisted.python.failure import Failure

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.api.filtering import Filter
from synapse.handlers.room import ShutdownRoomResponse
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.state import StateFilter
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, Requester
from synapse.util.async_helpers import ReadWriteLock
from synapse.util.stringutils import random_string
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


@attr.s(slots=True, auto_attribs=True)
class PurgeStatus:
    """Object tracking the status of a purge request

    This class contains information on the progress of a purge request, for
    return by get_purge_status.
    """

    STATUS_ACTIVE = 0
    STATUS_COMPLETE = 1
    STATUS_FAILED = 2

    STATUS_TEXT = {
        STATUS_ACTIVE: "active",
        STATUS_COMPLETE: "complete",
        STATUS_FAILED: "failed",
    }

    # Save the error message if an error occurs
    error: str = ""

    # Tracks whether this request has completed. One of STATUS_{ACTIVE,COMPLETE,FAILED}.
    status: int = STATUS_ACTIVE

    def asdict(self) -> JsonDict:
        ret = {"status": PurgeStatus.STATUS_TEXT[self.status]}
        if self.error:
            ret["error"] = self.error
        return ret


@attr.s(slots=True, auto_attribs=True)
class DeleteStatus:
    """Object tracking the status of a delete room request

    This class contains information on the progress of a delete room request, for
    return by get_delete_status.
    """

    STATUS_PURGING = 0
    STATUS_COMPLETE = 1
    STATUS_FAILED = 2
    STATUS_SHUTTING_DOWN = 3

    STATUS_TEXT = {
        STATUS_PURGING: "purging",
        STATUS_COMPLETE: "complete",
        STATUS_FAILED: "failed",
        STATUS_SHUTTING_DOWN: "shutting_down",
    }

    # Tracks whether this request has completed.
    # One of STATUS_{PURGING,COMPLETE,FAILED,SHUTTING_DOWN}.
    status: int = STATUS_PURGING

    # Save the error message if an error occurs
    error: str = ""

    # Saves the result of an action to give it back to REST API
    shutdown_room: ShutdownRoomResponse = {
        "kicked_users": [],
        "failed_to_kick_users": [],
        "local_aliases": [],
        "new_room_id": None,
    }

    def asdict(self) -> JsonDict:
        ret = {
            "status": DeleteStatus.STATUS_TEXT[self.status],
            "shutdown_room": self.shutdown_room,
        }
        if self.error:
            ret["error"] = self.error
        return ret


class PaginationHandler:
    """Handles pagination and purge history requests.

    These are in the same handler due to the fact we need to block clients
    paginating during a purge.
    """

    # when to remove a completed deletion/purge from the results map
    CLEAR_PURGE_AFTER_MS = 1000 * 3600 * 24  # 24 hours

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.storage = hs.get_storage()
        self.state_store = self.storage.state
        self.clock = hs.get_clock()
        self._server_name = hs.hostname
        self._room_shutdown_handler = hs.get_room_shutdown_handler()

        self.pagination_lock = ReadWriteLock()
        # IDs of rooms in which there currently an active purge *or delete* operation.
        self._purges_in_progress_by_room: Set[str] = set()
        # map from purge id to PurgeStatus
        self._purges_by_id: Dict[str, PurgeStatus] = {}
        # map from purge id to DeleteStatus
        self._delete_by_id: Dict[str, DeleteStatus] = {}
        # map from room id to delete ids
        # Dict[`room_id`, List[`delete_id`]]
        self._delete_by_room: Dict[str, List[str]] = {}
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

        if (
            hs.config.worker.run_background_tasks
            and hs.config.retention.retention_enabled
        ):
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
                retention_policy["max_lifetime"] or self._retention_default_max_lifetime
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

            self._purges_by_id[purge_id] = PurgeStatus()

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
            )

    def start_purge_history(
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

        self._purges_by_id[purge_id] = PurgeStatus()
        run_as_background_process(
            "purge_history",
            self._purge_history,
            purge_id,
            room_id,
            token,
            delete_local_events,
        )
        return purge_id

    async def _purge_history(
        self, purge_id: str, room_id: str, token: str, delete_local_events: bool
    ) -> None:
        """Carry out a history purge on a room.

        Args:
            purge_id: The ID for this purge.
            room_id: The room to purge from
            token: topological token to delete events before
            delete_local_events: True to delete local events as well as remote ones
        """
        self._purges_in_progress_by_room.add(room_id)
        try:
            async with self.pagination_lock.write(room_id):
                await self.storage.purge_events.purge_history(
                    room_id, token, delete_local_events
                )
            logger.info("[purge] complete")
            self._purges_by_id[purge_id].status = PurgeStatus.STATUS_COMPLETE
        except Exception:
            f = Failure()
            logger.error(
                "[purge] failed", exc_info=(f.type, f.value, f.getTracebackObject())  # type: ignore
            )
            self._purges_by_id[purge_id].status = PurgeStatus.STATUS_FAILED
            self._purges_by_id[purge_id].error = f.getErrorMessage()
        finally:
            self._purges_in_progress_by_room.discard(room_id)

            # remove the purge from the list 24 hours after it completes
            def clear_purge() -> None:
                del self._purges_by_id[purge_id]

            self.hs.get_reactor().callLater(
                PaginationHandler.CLEAR_PURGE_AFTER_MS / 1000, clear_purge
            )

    def get_purge_status(self, purge_id: str) -> Optional[PurgeStatus]:
        """Get the current status of an active purge

        Args:
            purge_id: purge_id returned by start_purge_history
        """
        return self._purges_by_id.get(purge_id)

    def get_delete_status(self, delete_id: str) -> Optional[DeleteStatus]:
        """Get the current status of an active deleting

        Args:
            delete_id: delete_id returned by start_shutdown_and_purge_room
        """
        return self._delete_by_id.get(delete_id)

    def get_delete_ids_by_room(self, room_id: str) -> Optional[Collection[str]]:
        """Get all active delete ids by room

        Args:
            room_id: room_id that is deleted
        """
        return self._delete_by_room.get(room_id)

    async def purge_room(self, room_id: str, force: bool = False) -> None:
        """Purge the given room from the database.
        This function is part the delete room v1 API.

        Args:
            room_id: room to be purged
            force: set true to skip checking for joined users.
        """
        async with self.pagination_lock.write(room_id):
            # first check that we have no users in this room
            if not force:
                joined = await self.store.is_host_joined(room_id, self._server_name)
                if joined:
                    raise SynapseError(400, "Users are still joined to this room")

            await self.storage.purge_events.purge_room(room_id)

    async def get_messages(
        self,
        requester: Requester,
        room_id: str,
        pagin_config: PaginationConfig,
        as_client_event: bool = True,
        event_filter: Optional[Filter] = None,
    ) -> Dict[str, Any]:
        """Get messages in a room.

        Args:
            requester: The user requesting messages.
            room_id: The room they want messages from.
            pagin_config: The pagination config rules to apply, if any.
            as_client_event: True to get events in client-server format.
            event_filter: Filter to apply to results or None
        Returns:
            Pagination API results
        """
        user_id = requester.user.to_string()

        if pagin_config.from_token:
            from_token = pagin_config.from_token
        else:
            from_token = self.hs.get_event_sources().get_current_token_for_pagination()

        if pagin_config.limit is None:
            # This shouldn't happen as we've set a default limit before this
            # gets called.
            raise Exception("limit not set")

        room_token = from_token.room_key

        async with self.pagination_lock.read(room_id):
            (
                membership,
                member_event_id,
            ) = await self.auth.check_user_in_room_or_world_readable(
                room_id, user_id, allow_departed_users=True
            )

            if pagin_config.direction == "b":
                # if we're going backwards, we might need to backfill. This
                # requires that we have a topo token.
                if room_token.topological:
                    curr_topo = room_token.topological
                else:
                    curr_topo = await self.store.get_current_topological_token(
                        room_id, room_token.stream
                    )

                if membership == Membership.LEAVE:
                    # If they have left the room then clamp the token to be before
                    # they left the room, to save the effort of loading from the
                    # database.

                    # This is only None if the room is world_readable, in which
                    # case "JOIN" would have been returned.
                    assert member_event_id

                    leave_token = await self.store.get_topological_token_for_event(
                        member_event_id
                    )
                    assert leave_token.topological is not None

                    if leave_token.topological < curr_topo:
                        from_token = from_token.copy_and_replace(
                            "room_key", leave_token
                        )

                await self.hs.get_federation_handler().maybe_backfill(
                    room_id,
                    curr_topo,
                    limit=pagin_config.limit,
                )

            to_room_key = None
            if pagin_config.to_token:
                to_room_key = pagin_config.to_token.room_key

            events, next_key = await self.store.paginate_room_events(
                room_id=room_id,
                from_key=from_token.room_key,
                to_key=to_room_key,
                direction=pagin_config.direction,
                limit=pagin_config.limit,
                event_filter=event_filter,
            )

            next_token = from_token.copy_and_replace("room_key", next_key)

        if events:
            if event_filter:
                events = await event_filter.filter(events)

            events = await filter_events_for_client(
                self.storage, user_id, events, is_peeking=(member_event_id is None)
            )

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

            state_ids = await self.state_store.get_state_ids_for_event(
                events[0].event_id, state_filter=state_filter
            )

            if state_ids:
                state_dict = await self.store.get_events(list(state_ids.values()))
                state = state_dict.values()

        aggregations = await self.store.get_bundled_aggregations(events, user_id)

        time_now = self.clock.time_msec()

        chunk = {
            "chunk": (
                self._event_serializer.serialize_events(
                    events,
                    time_now,
                    bundle_aggregations=aggregations,
                    as_client_event=as_client_event,
                )
            ),
            "start": await from_token.to_string(self.store),
            "end": await next_token.to_string(self.store),
        }

        if state:
            chunk["state"] = self._event_serializer.serialize_events(
                state, time_now, as_client_event=as_client_event
            )

        return chunk

    async def _shutdown_and_purge_room(
        self,
        delete_id: str,
        room_id: str,
        requester_user_id: str,
        new_room_user_id: Optional[str] = None,
        new_room_name: Optional[str] = None,
        message: Optional[str] = None,
        block: bool = False,
        purge: bool = True,
        force_purge: bool = False,
    ) -> None:
        """
        Shuts down and purges a room.

        See `RoomShutdownHandler.shutdown_room` for details of creation of the new room

        Args:
            delete_id: The ID for this delete.
            room_id: The ID of the room to shut down.
            requester_user_id:
                User who requested the action. Will be recorded as putting the room on the
                blocking list.
            new_room_user_id:
                If set, a new room will be created with this user ID
                as the creator and admin, and all users in the old room will be
                moved into that room. If not set, no new room will be created
                and the users will just be removed from the old room.
            new_room_name:
                A string representing the name of the room that new users will
                be invited to. Defaults to `Content Violation Notification`
            message:
                A string containing the first message that will be sent as
                `new_room_user_id` in the new room. Ideally this will clearly
                convey why the original room was shut down.
                Defaults to `Sharing illegal content on this server is not
                permitted and rooms in violation will be blocked.`
            block:
                If set to `true`, this room will be added to a blocking list,
                preventing future attempts to join the room. Defaults to `false`.
            purge:
                If set to `true`, purge the given room from the database.
            force_purge:
                If set to `true`, the room will be purged from database
                also if it fails to remove some users from room.

        Saves a `RoomShutdownHandler.ShutdownRoomResponse` in `DeleteStatus`:
        """

        self._purges_in_progress_by_room.add(room_id)
        try:
            async with self.pagination_lock.write(room_id):
                self._delete_by_id[delete_id].status = DeleteStatus.STATUS_SHUTTING_DOWN
                self._delete_by_id[
                    delete_id
                ].shutdown_room = await self._room_shutdown_handler.shutdown_room(
                    room_id=room_id,
                    requester_user_id=requester_user_id,
                    new_room_user_id=new_room_user_id,
                    new_room_name=new_room_name,
                    message=message,
                    block=block,
                )
                self._delete_by_id[delete_id].status = DeleteStatus.STATUS_PURGING

                if purge:
                    logger.info("starting purge room_id %s", room_id)

                    # first check that we have no users in this room
                    if not force_purge:
                        joined = await self.store.is_host_joined(
                            room_id, self._server_name
                        )
                        if joined:
                            raise SynapseError(
                                400, "Users are still joined to this room"
                            )

                    await self.storage.purge_events.purge_room(room_id)

            logger.info("complete")
            self._delete_by_id[delete_id].status = DeleteStatus.STATUS_COMPLETE
        except Exception:
            f = Failure()
            logger.error(
                "failed",
                exc_info=(f.type, f.value, f.getTracebackObject()),  # type: ignore
            )
            self._delete_by_id[delete_id].status = DeleteStatus.STATUS_FAILED
            self._delete_by_id[delete_id].error = f.getErrorMessage()
        finally:
            self._purges_in_progress_by_room.discard(room_id)

            # remove the delete from the list 24 hours after it completes
            def clear_delete() -> None:
                del self._delete_by_id[delete_id]
                self._delete_by_room[room_id].remove(delete_id)
                if not self._delete_by_room[room_id]:
                    del self._delete_by_room[room_id]

            self.hs.get_reactor().callLater(
                PaginationHandler.CLEAR_PURGE_AFTER_MS / 1000, clear_delete
            )

    def start_shutdown_and_purge_room(
        self,
        room_id: str,
        requester_user_id: str,
        new_room_user_id: Optional[str] = None,
        new_room_name: Optional[str] = None,
        message: Optional[str] = None,
        block: bool = False,
        purge: bool = True,
        force_purge: bool = False,
    ) -> str:
        """Start off shut down and purge on a room.

        Args:
            room_id: The ID of the room to shut down.
            requester_user_id:
                User who requested the action and put the room on the
                blocking list.
            new_room_user_id:
                If set, a new room will be created with this user ID
                as the creator and admin, and all users in the old room will be
                moved into that room. If not set, no new room will be created
                and the users will just be removed from the old room.
            new_room_name:
                A string representing the name of the room that new users will
                be invited to. Defaults to `Content Violation Notification`
            message:
                A string containing the first message that will be sent as
                `new_room_user_id` in the new room. Ideally this will clearly
                convey why the original room was shut down.
                Defaults to `Sharing illegal content on this server is not
                permitted and rooms in violation will be blocked.`
            block:
                If set to `true`, this room will be added to a blocking list,
                preventing future attempts to join the room. Defaults to `false`.
            purge:
                If set to `true`, purge the given room from the database.
            force_purge:
                If set to `true`, the room will be purged from database
                also if it fails to remove some users from room.

        Returns:
            unique ID for this delete transaction.
        """
        if room_id in self._purges_in_progress_by_room:
            raise SynapseError(
                400, "History purge already in progress for %s" % (room_id,)
            )

        # This check is double to `RoomShutdownHandler.shutdown_room`
        # But here the requester get a direct response / error with HTTP request
        # and do not have to check the purge status
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

        self._delete_by_id[delete_id] = DeleteStatus()
        self._delete_by_room.setdefault(room_id, []).append(delete_id)
        run_as_background_process(
            "shutdown_and_purge_room",
            self._shutdown_and_purge_room,
            delete_id,
            room_id,
            requester_user_id,
            new_room_user_id,
            new_room_name,
            message,
            block,
            purge,
            force_purge,
        )
        return delete_id
