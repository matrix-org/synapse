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
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

import attr
from prometheus_client import Counter

from twisted.internet import defer

from synapse.api.constants import EduTypes, EventTypes, HistoryVisibility, Membership
from synapse.api.errors import AuthError
from synapse.events import EventBase
from synapse.handlers.presence import format_user_presence_state
from synapse.logging import issue9533_logger
from synapse.logging.context import PreserveLoggingContext
from synapse.logging.opentracing import log_kv, start_active_span
from synapse.metrics import LaterGauge
from synapse.streams.config import PaginationConfig
from synapse.types import (
    JsonDict,
    PersistedEventPosition,
    RoomStreamToken,
    StreamKeyType,
    StreamToken,
    UserID,
)
from synapse.util.async_helpers import ObservableDeferred, timeout_deferred
from synapse.util.metrics import Measure
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer

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
    """This represents a single client connection to the events stream.
    The events stream handler will have yielded to the deferred, so to
    notify the handler it is sufficient to resolve the deferred.
    """

    __slots__ = ["deferred"]

    def __init__(self, deferred: "defer.Deferred"):
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

        self.notify_deferred: ObservableDeferred[StreamToken] = ObservableDeferred(
            defer.Deferred()
        )

    def notify(
        self,
        stream_key: str,
        stream_id: Union[int, RoomStreamToken],
        time_now_ms: int,
    ) -> None:
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
        notify_deferred = self.notify_deferred

        log_kv(
            {
                "notify": self.user_id,
                "stream": stream_key,
                "stream_id": stream_id,
                "listeners": self.count_listeners(),
            }
        )

        users_woken_by_stream_counter.labels(stream_key).inc()

        with PreserveLoggingContext():
            self.notify_deferred = ObservableDeferred(defer.Deferred())
            notify_deferred.callback(self.current_token)

    def remove(self, notifier: "Notifier") -> None:
        """Remove this listener from all the indexes in the Notifier
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


@attr.s(slots=True, frozen=True, auto_attribs=True)
class EventStreamResult:
    events: List[Union[JsonDict, EventBase]]
    start_token: StreamToken
    end_token: StreamToken

    def __bool__(self) -> bool:
        return bool(self.events)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _PendingRoomEventEntry:
    event_pos: PersistedEventPosition
    extra_users: Collection[UserID]

    room_id: str
    type: str
    state_key: Optional[str]
    membership: Optional[str]


class Notifier:
    """This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    UNUSED_STREAM_EXPIRY_MS = 10 * 60 * 1000

    def __init__(self, hs: "HomeServer"):
        self.user_to_user_stream: Dict[str, _NotifierUserStream] = {}
        self.room_to_user_streams: Dict[str, Set[_NotifierUserStream]] = {}

        self.hs = hs
        self._storage_controllers = hs.get_storage_controllers()
        self.event_sources = hs.get_event_sources()
        self.store = hs.get_datastores().main
        self.pending_new_room_events: List[_PendingRoomEventEntry] = []

        # Called when there are new things to stream over replication
        self.replication_callbacks: List[Callable[[], None]] = []
        self._new_join_in_room_callbacks: List[Callable[[str, str], None]] = []

        self._federation_client = hs.get_federation_http_client()

        self._third_party_rules = hs.get_third_party_event_rules()

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
        def count_listeners() -> int:
            all_user_streams: Set[_NotifierUserStream] = set()

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

    def add_replication_callback(self, cb: Callable[[], None]) -> None:
        """Add a callback that will be called when some new data is available.
        Callback is not given any arguments. It should *not* return a Deferred - if
        it needs to do any asynchronous work, a background thread should be started and
        wrapped with run_as_background_process.
        """
        self.replication_callbacks.append(cb)

    def add_new_join_in_room_callback(self, cb: Callable[[str, str], None]) -> None:
        """Add a callback that will be called when a user joins a room.

        This only fires on genuine membership changes, e.g. "invite" -> "join".
        Membership transitions like "join" -> "join" (for e.g. displayname changes) do
        not trigger the callback.

        When called, the callback receives two arguments: the event ID and the room ID.
        It should *not* return a Deferred - if it needs to do any asynchronous work, a
        background thread should be started and wrapped with run_as_background_process.
        """
        self._new_join_in_room_callbacks.append(cb)

    async def on_new_room_event(
        self,
        event: EventBase,
        event_pos: PersistedEventPosition,
        max_room_stream_token: RoomStreamToken,
        extra_users: Optional[Collection[UserID]] = None,
    ) -> None:
        """Unwraps event and calls `on_new_room_event_args`."""
        await self.on_new_room_event_args(
            event_pos=event_pos,
            room_id=event.room_id,
            event_id=event.event_id,
            event_type=event.type,
            state_key=event.get("state_key"),
            membership=event.content.get("membership"),
            max_room_stream_token=max_room_stream_token,
            extra_users=extra_users or [],
        )

    async def on_new_room_event_args(
        self,
        room_id: str,
        event_id: str,
        event_type: str,
        state_key: Optional[str],
        membership: Optional[str],
        event_pos: PersistedEventPosition,
        max_room_stream_token: RoomStreamToken,
        extra_users: Optional[Collection[UserID]] = None,
    ) -> None:
        """Used by handlers to inform the notifier something has happened
        in the room, room event wise.

        This triggers the notifier to wake up any listeners that are
        listening to the room, and any listeners for the users in the
        `extra_users` param.

        This also notifies modules listening on new events via the
        `on_new_event` callback.

        The events can be persisted out of order. The notifier will wait
        until all previous events have been persisted before notifying
        the client streams.
        """
        self.pending_new_room_events.append(
            _PendingRoomEventEntry(
                event_pos=event_pos,
                extra_users=extra_users or [],
                room_id=room_id,
                type=event_type,
                state_key=state_key,
                membership=membership,
            )
        )
        self._notify_pending_new_room_events(max_room_stream_token)

        await self._third_party_rules.on_new_event(event_id)

        self.notify_replication()

    def _notify_pending_new_room_events(
        self, max_room_stream_token: RoomStreamToken
    ) -> None:
        """Notify for the room events that were queued waiting for a previous
        event to be persisted.
        Args:
            max_room_stream_token: The highest stream_id below which all
                events have been persisted.
        """
        pending = self.pending_new_room_events
        self.pending_new_room_events = []

        users: Set[UserID] = set()
        rooms: Set[str] = set()

        for entry in pending:
            if entry.event_pos.persisted_after(max_room_stream_token):
                self.pending_new_room_events.append(entry)
            else:
                if (
                    entry.type == EventTypes.Member
                    and entry.membership == Membership.JOIN
                    and entry.state_key
                ):
                    self._user_joined_room(entry.state_key, entry.room_id)

                users.update(entry.extra_users)
                rooms.add(entry.room_id)

        if users or rooms:
            self.on_new_event(
                StreamKeyType.ROOM,
                max_room_stream_token,
                users=users,
                rooms=rooms,
            )
            self._on_updated_room_token(max_room_stream_token)

    def _on_updated_room_token(self, max_room_stream_token: RoomStreamToken) -> None:
        """Poke services that might care that the room position has been
        updated.
        """

        # poke any interested application service.
        self._notify_app_services(max_room_stream_token)
        self._notify_pusher_pool(max_room_stream_token)

        if self.federation_sender:
            self.federation_sender.notify_new_events(max_room_stream_token)

    def _notify_app_services(self, max_room_stream_token: RoomStreamToken) -> None:
        try:
            self.appservice_handler.notify_interested_services(max_room_stream_token)
        except Exception:
            logger.exception("Error notifying application services of event")

    def _notify_pusher_pool(self, max_room_stream_token: RoomStreamToken) -> None:
        try:
            self._pusher_pool.on_new_notifications(max_room_stream_token)
        except Exception:
            logger.exception("Error pusher pool of event")

    def on_new_event(
        self,
        stream_key: str,
        new_token: Union[int, RoomStreamToken],
        users: Optional[Collection[Union[str, UserID]]] = None,
        rooms: Optional[Collection[str]] = None,
    ) -> None:
        """Used to inform listeners that something has happened event wise.

        Will wake up all listeners for the given users and rooms.

        Args:
            stream_key: The stream the event came from.
            new_token: The value of the new stream token.
            users: The users that should be informed of the new event.
            rooms: A collection of room IDs for which each joined member will be
                informed of the new event.
        """
        users = users or []
        rooms = rooms or []

        with Measure(self.clock, "on_new_event"):
            user_streams = set()

            log_kv(
                {
                    "waking_up_explicit_users": len(users),
                    "waking_up_explicit_rooms": len(rooms),
                }
            )

            for user in users:
                user_stream = self.user_to_user_stream.get(str(user))
                if user_stream is not None:
                    user_streams.add(user_stream)

            for room in rooms:
                user_streams |= self.room_to_user_streams.get(room, set())

            if stream_key == StreamKeyType.TO_DEVICE:
                issue9533_logger.debug(
                    "to-device messages stream id %s, awaking streams for %s",
                    new_token,
                    users,
                )

            time_now_ms = self.clock.time_msec()
            for user_stream in user_streams:
                try:
                    user_stream.notify(stream_key, new_token, time_now_ms)
                except Exception:
                    logger.exception("Failed to notify listener")

            self.notify_replication()

            # Notify appservices.
            try:
                self.appservice_handler.notify_interested_services_ephemeral(
                    stream_key,
                    new_token,
                    users,
                )
            except Exception:
                logger.exception(
                    "Error notifying application services of ephemeral events"
                )

    def on_new_replication_data(self) -> None:
        """Used to inform replication listeners that something has happened
        without waking up any of the normal user event streams"""
        self.notify_replication()

    async def wait_for_events(
        self,
        user_id: str,
        timeout: int,
        callback: Callable[[StreamToken, StreamToken], Awaitable[T]],
        room_ids: Optional[Collection[str]] = None,
        from_token: StreamToken = StreamToken.START,
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
                with start_active_span("wait_for_events"):
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

                        log_kv(
                            {
                                "wait_for_events": "sleep",
                                "token": prev_token,
                            }
                        )

                        with PreserveLoggingContext():
                            await listener.deferred

                        log_kv(
                            {
                                "wait_for_events": "woken",
                                "token": user_stream.current_token,
                            }
                        )

                        current_token = user_stream.current_token

                        result = await callback(prev_token, current_token)
                        log_kv(
                            {
                                "wait_for_events": "result",
                                "result": bool(result),
                            }
                        )
                        if result:
                            break

                        # Update the prev_token to the current_token since nothing
                        # has happened between the old prev_token and the current_token
                        prev_token = current_token
                    except defer.TimeoutError:
                        log_kv({"wait_for_events": "timeout"})
                        break
                    except defer.CancelledError:
                        log_kv({"wait_for_events": "cancelled"})
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
        explicit_room_id: Optional[str] = None,
    ) -> EventStreamResult:
        """For the given user and rooms, return any new events for them. If
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
                return EventStreamResult([], from_token, from_token)

            # The events fetched from each source are a JsonDict, EventBase, or
            # UserPresenceState, but see below for UserPresenceState being
            # converted to JsonDict.
            events: List[Union[JsonDict, EventBase]] = []
            end_token = from_token

            for name, source in self.event_sources.sources.get_sources():
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
                        self._storage_controllers,
                        user.to_string(),
                        new_events,
                        is_peeking=is_peeking,
                    )
                elif name == "presence":
                    now = self.clock.time_msec()
                    new_events[:] = [
                        {
                            "type": EduTypes.PRESENCE,
                            "content": format_user_presence_state(event, now),
                        }
                        for event in new_events
                    ]

                events.extend(new_events)
                end_token = end_token.copy_and_replace(keyname, new_key)

            return EventStreamResult(events, from_token, end_token)

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
        state = await self._storage_controllers.state.get_current_state_event(
            room_id, EventTypes.RoomHistoryVisibility, ""
        )
        if state and "history_visibility" in state.content:
            return (
                state.content["history_visibility"] == HistoryVisibility.WORLD_READABLE
            )
        else:
            return False

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

    def _register_with_keys(self, user_stream: _NotifierUserStream) -> None:
        self.user_to_user_stream[user_stream.user_id] = user_stream

        for room in user_stream.rooms:
            s = self.room_to_user_streams.setdefault(room, set())
            s.add(user_stream)

    def _user_joined_room(self, user_id: str, room_id: str) -> None:
        new_user_stream = self.user_to_user_stream.get(user_id)
        if new_user_stream is not None:
            room_streams = self.room_to_user_streams.setdefault(room_id, set())
            room_streams.add(new_user_stream)
            new_user_stream.rooms.add(room_id)

    def notify_replication(self) -> None:
        """Notify the any replication listeners that there's a new event"""
        for cb in self.replication_callbacks:
            cb()

    def notify_user_joined_room(self, event_id: str, room_id: str) -> None:
        for cb in self._new_join_in_room_callbacks:
            cb(event_id, room_id)

    def notify_remote_server_up(self, server: str) -> None:
        """Notify any replication that a remote server has come back up"""
        # We call federation_sender directly rather than registering as a
        # callback as a) we already have a reference to it and b) it introduces
        # circular dependencies.
        if self.federation_sender:
            self.federation_sender.wake_destination(server)

        # Tell the federation client about the fact the server is back up, so
        # that any in flight requests can be immediately retried.
        self._federation_client.wake_destination(server)
