# -*- coding: utf-8 -*-
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

from twisted.internet import defer
from twisted.python.failure import Failure

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.storage.state import StateFilter
from synapse.types import RoomStreamToken
from synapse.util.async_helpers import ReadWriteLock
from synapse.util.logcontext import run_in_background
from synapse.util.stringutils import random_string
from synapse.visibility import filter_events_for_client

logger = logging.getLogger(__name__)


class PurgeStatus(object):
    """Object tracking the status of a purge request

    This class contains information on the progress of a purge request, for
    return by get_purge_status.

    Attributes:
        status (int): Tracks whether this request has completed. One of
            STATUS_{ACTIVE,COMPLETE,FAILED}
    """

    STATUS_ACTIVE = 0
    STATUS_COMPLETE = 1
    STATUS_FAILED = 2

    STATUS_TEXT = {
        STATUS_ACTIVE: "active",
        STATUS_COMPLETE: "complete",
        STATUS_FAILED: "failed",
    }

    def __init__(self):
        self.status = PurgeStatus.STATUS_ACTIVE

    def asdict(self):
        return {"status": PurgeStatus.STATUS_TEXT[self.status]}


class PaginationHandler(object):
    """Handles pagination and purge history requests.

    These are in the same handler due to the fact we need to block clients
    paginating during a purge.
    """

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

        self.pagination_lock = ReadWriteLock()
        self._purges_in_progress_by_room = set()
        # map from purge id to PurgeStatus
        self._purges_by_id = {}
        self._event_serializer = hs.get_event_client_serializer()

    def start_purge_history(self, room_id, token, delete_local_events=False):
        """Start off a history purge on a room.

        Args:
            room_id (str): The room to purge from

            token (str): topological token to delete events before
            delete_local_events (bool): True to delete local events as well as
                remote ones

        Returns:
            str: unique ID for this purge transaction.
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
        run_in_background(
            self._purge_history, purge_id, room_id, token, delete_local_events
        )
        return purge_id

    @defer.inlineCallbacks
    def _purge_history(self, purge_id, room_id, token, delete_local_events):
        """Carry out a history purge on a room.

        Args:
            purge_id (str): The id for this purge
            room_id (str): The room to purge from
            token (str): topological token to delete events before
            delete_local_events (bool): True to delete local events as well as
                remote ones

        Returns:
            Deferred
        """
        self._purges_in_progress_by_room.add(room_id)
        try:
            with (yield self.pagination_lock.write(room_id)):
                yield self.store.purge_history(room_id, token, delete_local_events)
            logger.info("[purge] complete")
            self._purges_by_id[purge_id].status = PurgeStatus.STATUS_COMPLETE
        except Exception:
            f = Failure()
            logger.error(
                "[purge] failed", exc_info=(f.type, f.value, f.getTracebackObject())
            )
            self._purges_by_id[purge_id].status = PurgeStatus.STATUS_FAILED
        finally:
            self._purges_in_progress_by_room.discard(room_id)

            # remove the purge from the list 24 hours after it completes
            def clear_purge():
                del self._purges_by_id[purge_id]

            self.hs.get_reactor().callLater(24 * 3600, clear_purge)

    def get_purge_status(self, purge_id):
        """Get the current status of an active purge

        Args:
            purge_id (str): purge_id returned by start_purge_history

        Returns:
            PurgeStatus|None
        """
        return self._purges_by_id.get(purge_id)

    @defer.inlineCallbacks
    def get_messages(
        self,
        requester,
        room_id=None,
        pagin_config=None,
        as_client_event=True,
        event_filter=None,
    ):
        """Get messages in a room.

        Args:
            requester (Requester): The user requesting messages.
            room_id (str): The room they want messages from.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
                config rules to apply, if any.
            as_client_event (bool): True to get events in client-server format.
            event_filter (Filter): Filter to apply to results or None
        Returns:
            dict: Pagination API results
        """
        user_id = requester.user.to_string()

        if pagin_config.from_token:
            room_token = pagin_config.from_token.room_key
        else:
            pagin_config.from_token = (
                yield self.hs.get_event_sources().get_current_token_for_pagination()
            )
            room_token = pagin_config.from_token.room_key

        room_token = RoomStreamToken.parse(room_token)

        pagin_config.from_token = pagin_config.from_token.copy_and_replace(
            "room_key", str(room_token)
        )

        source_config = pagin_config.get_source_config("room")

        with (yield self.pagination_lock.read(room_id)):
            membership, member_event_id = yield self.auth.check_in_room_or_world_readable(
                room_id, user_id
            )

            if source_config.direction == "b":
                # if we're going backwards, we might need to backfill. This
                # requires that we have a topo token.
                if room_token.topological:
                    max_topo = room_token.topological
                else:
                    max_topo = yield self.store.get_max_topological_token(
                        room_id, room_token.stream
                    )

                if membership == Membership.LEAVE:
                    # If they have left the room then clamp the token to be before
                    # they left the room, to save the effort of loading from the
                    # database.
                    leave_token = yield self.store.get_topological_token_for_event(
                        member_event_id
                    )
                    leave_token = RoomStreamToken.parse(leave_token)
                    if leave_token.topological < max_topo:
                        source_config.from_key = str(leave_token)

                yield self.hs.get_handlers().federation_handler.maybe_backfill(
                    room_id, max_topo
                )

            events, next_key = yield self.store.paginate_room_events(
                room_id=room_id,
                from_key=source_config.from_key,
                to_key=source_config.to_key,
                direction=source_config.direction,
                limit=source_config.limit,
                event_filter=event_filter,
            )

            next_token = pagin_config.from_token.copy_and_replace("room_key", next_key)

        if events:
            if event_filter:
                events = event_filter.filter(events)

            events = yield filter_events_for_client(
                self.store, user_id, events, is_peeking=(member_event_id is None)
            )

        if not events:
            defer.returnValue(
                {
                    "chunk": [],
                    "start": pagin_config.from_token.to_string(),
                    "end": next_token.to_string(),
                }
            )

        state = None
        if event_filter and event_filter.lazy_load_members() and len(events) > 0:
            # TODO: remove redundant members

            # FIXME: we also care about invite targets etc.
            state_filter = StateFilter.from_types(
                (EventTypes.Member, event.sender) for event in events
            )

            state_ids = yield self.store.get_state_ids_for_event(
                events[0].event_id, state_filter=state_filter
            )

            if state_ids:
                state = yield self.store.get_events(list(state_ids.values()))
                state = state.values()

        time_now = self.clock.time_msec()

        chunk = {
            "chunk": (
                yield self._event_serializer.serialize_events(
                    events, time_now, as_client_event=as_client_event
                )
            ),
            "start": pagin_config.from_token.to_string(),
            "end": next_token.to_string(),
        }

        if state:
            chunk["state"] = (
                yield self._event_serializer.serialize_events(
                    state, time_now, as_client_event=as_client_event
                )
            )

        defer.returnValue(chunk)
