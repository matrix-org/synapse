# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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
from typing import (
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from prometheus_client import Counter

from twisted.internet import defer

import synapse.server
from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import AuthError
from synapse.events import EventBase
from synapse.handlers.presence import format_user_presence_state
from synapse.logging.context import PreserveLoggingContext
from synapse.logging.utils import log_function
from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.streams.config import PaginationConfig
from synapse.types import (
    Collection,
    PersistedEventPosition,
    RoomStreamToken,
    StreamToken,
    UserID,
)
from synapse.util.async_helpers import ObservableDeferred, timeout_deferred
from synapse.util.metrics import Measure
from synapse.visibility import filter_events_for_client

logger = logging.getLogger(__name__)

notified_events_counter = Counter("synapse_notifier_notified_events", "")

users_woken_by_stream_counter = Counter(
    "synapse_notifier_users_woken_by_stream", "", ["stream"]
)

T = TypeVar("T")


# TODO(paul): Should be shared somewhere
def count(func: Callable[[T], bool], it: Iterable[T]) -> int:
    """Return the number of items in it for which func returns true."""
    n = 0
    for x in it:
        if func(x):
            n += 1
    return n


class _NotificationListener:
    """ This represents a single client connection to the events stream.
    The events stream handler will have yielded to the deferred, so to
    notify the handler it is sufficient to resolve the deferred.
    """

    __slots__ = ["deferred"]

    def __init__(self, deferred):
        self.deferred = deferred


class _NotifierUserStream:
    """This represents a user connected to the event stream.
    It tracks the most recent stream token for that user.
    At a given point a user may have a number of streams listening for
    events.

    This listener will also keep track of which rooms it is listening in
    so that it can remove itself from the indexes in the Notifier class.
    """

    def __init__(
        self,
        user_id: str,
        rooms: Collection[str],
        current_token: StreamToken,
        time_now_ms: int,
    ):
        self.user_id = user_id
        self.rooms = set(rooms)
        self.current_token = current_token

        # The last token for which we should wake up any streams that have a
        # token that comes before it. This gets updated every time we get poked.
        # We start it at the current token since if we get any streams
        # that have a token from before we have no idea whether they should be
        # woken up or not, so lets just wake them up.
        self.last_notified_token = current_token
        self.last_notified_ms = time_now_ms

        with PreserveLoggingContext():
            self.notify_deferred = ObservableDeferred(defer.Deferred())

    def notify(
        self, stream_key: str, stream_id: Union[int, RoomStreamToken], time_now_ms: int,
    ):
        """Notify any listeners for this user of a new event from an
        event source.
        Args:
            stream_key: The stream the event came from.
            stream_id: The new id for the stream the event came from.
            time_now_ms: The current time in milliseconds.
        """
        self.current_token = self.current_token.copy_and_advance(stream_key, stream_id)
        self.last_notified_token = self.current_token
        self.last_notified_ms = time_now_ms
        noify_deferred = self.notify_deferred

        users_woken_by_stream_counter.labels(stream_key).inc()

        with PreserveLoggingContext():
            self.notify_deferred = ObservableDeferred(defer.Deferred())
            noify_deferred.callback(self.current_token)

    def remove(self, notifier: "Notifier"):
        """ Remove this listener from all the indexes in the Notifier
        it knows about.
        """

        for room in self.rooms:
            lst = notifier.room_to_user_streams.get(room, set())
            lst.discard(self)

        notifier.user_to_user_stream.pop(self.user_id)

    def count_listeners(self) -> int:
        return len(self.notify_deferred.observers())

    def new_listener(self, token: StreamToken) -> _NotificationListener:
        """Returns a deferred that is resolved when there is a new token
        greater than the given token.

        Args:
            token: The token from which we are streaming from, i.e. we shouldn't
                notify for things that happened before this.
        """
        # Immediately wake up stream if something has already since happened
        # since their last token.
        if self.last_notified_token != token:
            return _NotificationListener(defer.succeed(self.current_token))
        else:
            return _NotificationListener(self.notify_deferred.observe())


class EventStreamResult(namedtuple("EventStreamResult", ("events", "tokens"))):
    def __bool__(self):
        return bool(self.events)


class Notifier:
    """ This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    UNUSED_STREAM_EXPIRY_MS = 10 * 60 * 1000

    def __init__(self, hs: "synapse.server.HomeServer"):
        self.user_to_user_stream = {}  # type: Dict[str, _NotifierUserStream]
        self.room_to_user_streams = {}  # type: Dict[str, Set[_NotifierUserStream]]

        self.hs = hs
        self.storage = hs.get_storage()
        self.event_sources = hs.get_event_sources()
        self.store = hs.get_datastore()
        self.pending_new_room_events = (
            []
        )  # type: List[Tuple[PersistedEventPosition, EventBase, Collection[UserID]]]

        # Called when there are new things to stream over replication
        self.replication_callbacks = []  # type: List[Callable[[], None]]

        # Called when remote servers have come back online after having been
        # down.
        self.remote_server_up_callbacks = []  # type: List[Callable[[str], None]]

        self.clock = hs.get_clock()
        self.appservice_handler = hs.get_application_service_handler()
        self._pusher_pool = hs.get_pusherpool()

        self.federation_sender = None
        if hs.should_send_federation():
            self.federation_sender = hs.get_federation_sender()

        self.state_handler = hs.get_state_handler()

        self.clock.looping_call(
            self.remove_expired_streams, self.UNUSED_STREAM_EXPIRY_MS
        )

        # This is not a very cheap test to perform, but it's only executed
        # when rendering the metrics page, which is likely once per minute at
        # most when scraping it.
        def count_listeners():
            all_user_streams = set()  # type: Set[_NotifierUserStream]

            for streams in list(self.room_to_user_streams.values()):
                all_user_streams |= streams
            for stream in list(self.user_to_user_stream.values()):
                all_user_streams.add(stream)

            return sum(stream.count_listeners() for stream in all_user_streams)

        LaterGauge("synapse_notifier_listeners", "", [], count_listeners)

        LaterGauge(
            "synapse_notifier_rooms",
            "",
            [],
            lambda: count(bool, list(self.room_to_user_streams.values())),
        )
        LaterGauge(
            "synapse_notifier_users", "", [], lambda: len(self.user_to_user_stream)
        )

    def add_replication_callback(self, cb: Callable[[], None]):
        """Add a callback that will be called when some new data is available.
        Callback is not given any arguments. It should *not* return a Deferred - if
        it needs to do any asynchronous work, a background thread should be started and
        wrapped with run_as_background_process.
        """
        self.replication_callbacks.append(cb)

    def on_new_room_event(
        self,
        event: EventBase,
        event_pos: PersistedEventPosition,
        max_room_stream_token: RoomStreamToken,
        extra_users: Collection[UserID] = [],
    ):
        """ Used by handlers to inform the notifier something has happened
        in the room, room event wise.

        This triggers the notifier to wake up any listeners that are
        listening to the room, and any listeners for the users in the
        `extra_users` param.

        The events can be peristed out of order. The notifier will wait
        until all previous events have been persisted before notifying
        the client streams.
        """
        self.pending_new_room_events.append((event_pos, event, extra_users))
        self._notify_pending_new_room_events(max_room_stream_token)

        self.notify_replication()

    def _notify_pending_new_room_events(self, max_room_stream_token: RoomStreamToken):
        """Notify for the room events that were queued waiting for a previous
        event to be persisted.
        Args:
            max_room_stream_token: The highest stream_id below which all
                events have been persisted.
        """
        pending = self.pending_new_room_events
        self.pending_new_room_events = []

        users = set()  # type: Set[UserID]
        rooms = set()  # type: Set[str]

        for event_pos, event, extra_users in pending:
            if event_pos.persisted_after(max_room_stream_token):
                self.pending_new_room_events.append((event_pos, event, extra_users))
            else:
                if (
                    event.type == EventTypes.Member
                    and event.membership == Membership.JOIN
                ):
                    self._user_joined_room(event.state_key, event.room_id)

                users.update(extra_users)
                rooms.add(event.room_id)

        if users or rooms:
            self.on_new_event(
                "room_key", max_room_stream_token, users=users, rooms=rooms,
            )
            self._on_updated_room_token(max_room_stream_token)

    def _on_updated_room_token(self, max_room_stream_token: RoomStreamToken):
        """Poke services that might care that the room position has been
        updated.
        """

        # poke any interested application service.
        run_as_background_process(
            "_notify_app_services", self._notify_app_services, max_room_stream_token
        )

        run_as_background_process(
            "_notify_pusher_pool", self._notify_pusher_pool, max_room_stream_token
        )

        if self.federation_sender:
            self.federation_sender.notify_new_events(max_room_stream_token.stream)

    async def _notify_app_services(self, max_room_stream_token: RoomStreamToken):
        try:
            await self.appservice_handler.notify_interested_services(
                max_room_stream_token.stream
            )
        except Exception:
            logger.exception("Error notifying application services of event")

    async def _notify_pusher_pool(self, max_room_stream_token: RoomStreamToken):
        try:
            await self._pusher_pool.on_new_notifications(max_room_stream_token.stream)
        except Exception:
            logger.exception("Error pusher pool of event")

    def on_new_event(
        self,
        stream_key: str,
        new_token: Union[int, RoomStreamToken],
        users: Collection[UserID] = [],
        rooms: Collection[str] = [],
    ):
        """ Used to inform listeners that something has happened event wise.

        Will wake up all listeners for the given users and rooms.
        """
        with PreserveLoggingContext():
            with Measure(self.clock, "on_new_event"):
                user_streams = set()

                for user in users:
                    user_stream = self.user_to_user_stream.get(str(user))
                    if user_stream is not None:
                        user_streams.add(user_stream)

                for room in rooms:
                    user_streams |= self.room_to_user_streams.get(room, set())

                time_now_ms = self.clock.time_msec()
                for user_stream in user_streams:
                    try:
                        user_stream.notify(stream_key, new_token, time_now_ms)
                    except Exception:
                        logger.exception("Failed to notify listener")

                self.notify_replication()

    def on_new_replication_data(self) -> None:
        """Used to inform replication listeners that something has happend
        without waking up any of the normal user event streams"""
        self.notify_replication()

    async def wait_for_events(
        self,
        user_id: str,
        timeout: int,
        callback: Callable[[StreamToken, StreamToken], Awaitable[T]],
        room_ids=None,
        from_token=StreamToken.START,
    ) -> T:
        """Wait until the callback returns a non empty response or the
        timeout fires.
        """
        user_stream = self.user_to_user_stream.get(user_id)
        if user_stream is None:
            current_token = self.event_sources.get_current_token()
            if room_ids is None:
                room_ids = await self.store.get_rooms_for_user(user_id)
            user_stream = _NotifierUserStream(
                user_id=user_id,
                rooms=room_ids,
                current_token=current_token,
                time_now_ms=self.clock.time_msec(),
            )
            self._register_with_keys(user_stream)

        result = None
        prev_token = from_token
        if timeout:
            end_time = self.clock.time_msec() + timeout

            while not result:
                try:
                    now = self.clock.time_msec()
                    if end_time <= now:
                        break

                    # Now we wait for the _NotifierUserStream to be told there
                    # is a new token.
                    listener = user_stream.new_listener(prev_token)
                    listener.deferred = timeout_deferred(
                        listener.deferred,
                        (end_time - now) / 1000.0,
                        self.hs.get_reactor(),
                    )
                    with PreserveLoggingContext():
                        await listener.deferred

                    current_token = user_stream.current_token

                    result = await callback(prev_token, current_token)
                    if result:
                        break

                    # Update the prev_token to the current_token since nothing
                    # has happened between the old prev_token and the current_token
                    prev_token = current_token
                except defer.TimeoutError:
                    break
                except defer.CancelledError:
                    break

        if result is None:
            # This happened if there was no timeout or if the timeout had
            # already expired.
            current_token = user_stream.current_token
            result = await callback(prev_token, current_token)

        return result

    async def get_events_for(
        self,
        user: UserID,
        pagination_config: PaginationConfig,
        timeout: int,
        is_guest: bool = False,
        explicit_room_id: str = None,
    ) -> EventStreamResult:
        """ For the given user and rooms, return any new events for them. If
        there are no new events wait for up to `timeout` milliseconds for any
        new events to happen before returning.

        If explicit_room_id is not set, the user's joined rooms will be polled
        for events.
        If explicit_room_id is set, that room will be polled for events only if
        it is world readable or the user has joined the room.
        """
        if pagination_config.from_token:
            from_token = pagination_config.from_token
        else:
            from_token = self.event_sources.get_current_token()

        limit = pagination_config.limit

        room_ids, is_joined = await self._get_room_ids(user, explicit_room_id)
        is_peeking = not is_joined

        async def check_for_updates(
            before_token: StreamToken, after_token: StreamToken
        ) -> EventStreamResult:
            if after_token == before_token:
                return EventStreamResult([], (from_token, from_token))

            events = []  # type: List[EventBase]
            end_token = from_token

            for name, source in self.event_sources.sources.items():
                keyname = "%s_key" % name
                before_id = getattr(before_token, keyname)
                after_id = getattr(after_token, keyname)
                if before_id == after_id:
                    continue

                new_events, new_key = await source.get_new_events(
                    user=user,
                    from_key=getattr(from_token, keyname),
                    limit=limit,
                    is_guest=is_peeking,
                    room_ids=room_ids,
                    explicit_room_id=explicit_room_id,
                )

                if name == "room":
                    new_events = await filter_events_for_client(
                        self.storage,
                        user.to_string(),
                        new_events,
                        is_peeking=is_peeking,
                    )
                elif name == "presence":
                    now = self.clock.time_msec()
                    new_events[:] = [
                        {
                            "type": "m.presence",
                            "content": format_user_presence_state(event, now),
                        }
                        for event in new_events
                    ]

                events.extend(new_events)
                end_token = end_token.copy_and_replace(keyname, new_key)

            return EventStreamResult(events, (from_token, end_token))

        user_id_for_stream = user.to_string()
        if is_peeking:
            # Internally, the notifier keeps an event stream per user_id.
            # This is used by both /sync and /events.
            # We want /events to be used for peeking independently of /sync,
            # without polluting its contents. So we invent an illegal user ID
            # (which thus cannot clash with any real users) for keying peeking
            # over /events.
            #
            # I am sorry for what I have done.
            user_id_for_stream = "_PEEKING_%s_%s" % (
                explicit_room_id,
                user_id_for_stream,
            )

        result = await self.wait_for_events(
            user_id_for_stream,
            timeout,
            check_for_updates,
            room_ids=room_ids,
            from_token=from_token,
        )

        return result

    async def _get_room_ids(
        self, user: UserID, explicit_room_id: Optional[str]
    ) -> Tuple[Collection[str], bool]:
        joined_room_ids = await self.store.get_rooms_for_user(user.to_string())
        if explicit_room_id:
            if explicit_room_id in joined_room_ids:
                return [explicit_room_id], True
            if await self._is_world_readable(explicit_room_id):
                return [explicit_room_id], False
            raise AuthError(403, "Non-joined access not allowed")
        return joined_room_ids, True

    async def _is_world_readable(self, room_id: str) -> bool:
        state = await self.state_handler.get_current_state(
            room_id, EventTypes.RoomHistoryVisibility, ""
        )
        if state and "history_visibility" in state.content:
            return state.content["history_visibility"] == "world_readable"
        else:
            return False

    @log_function
    def remove_expired_streams(self) -> None:
        time_now_ms = self.clock.time_msec()
        expired_streams = []
        expire_before_ts = time_now_ms - self.UNUSED_STREAM_EXPIRY_MS
        for stream in self.user_to_user_stream.values():
            if stream.count_listeners():
                continue
            if stream.last_notified_ms < expire_before_ts:
                expired_streams.append(stream)

        for expired_stream in expired_streams:
            expired_stream.remove(self)

    @log_function
    def _register_with_keys(self, user_stream: _NotifierUserStream):
        self.user_to_user_stream[user_stream.user_id] = user_stream

        for room in user_stream.rooms:
            s = self.room_to_user_streams.setdefault(room, set())
            s.add(user_stream)

    def _user_joined_room(self, user_id: str, room_id: str):
        new_user_stream = self.user_to_user_stream.get(user_id)
        if new_user_stream is not None:
            room_streams = self.room_to_user_streams.setdefault(room_id, set())
            room_streams.add(new_user_stream)
            new_user_stream.rooms.add(room_id)

    def notify_replication(self) -> None:
        """Notify the any replication listeners that there's a new event"""
        for cb in self.replication_callbacks:
            cb()

    def notify_remote_server_up(self, server: str):
        """Notify any replication that a remote server has come back up
        """
        # We call federation_sender directly rather than registering as a
        # callback as a) we already have a reference to it and b) it introduces
        # circular dependencies.
        if self.federation_sender:
            self.federation_sender.wake_destination(server)
