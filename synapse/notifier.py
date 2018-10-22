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

from prometheus_client import Counter

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import AuthError
from synapse.handlers.presence import format_user_presence_state
from synapse.metrics import LaterGauge
from synapse.types import StreamToken
from synapse.util.async_helpers import (
    DeferredTimeoutError,
    ObservableDeferred,
    add_timeout_to_deferred,
)
from synapse.util.logcontext import PreserveLoggingContext, run_in_background
from synapse.util.logutils import log_function
from synapse.util.metrics import Measure
from synapse.visibility import filter_events_for_client

logger = logging.getLogger(__name__)

notified_events_counter = Counter("synapse_notifier_notified_events", "")

users_woken_by_stream_counter = Counter(
    "synapse_notifier_users_woken_by_stream", "", ["stream"])


# TODO(paul): Should be shared somewhere
def count(func, l):
    """Return the number of items in l for which func returns true."""
    n = 0
    for x in l:
        if func(x):
            n += 1
    return n


class _NotificationListener(object):
    """ This represents a single client connection to the events stream.
    The events stream handler will have yielded to the deferred, so to
    notify the handler it is sufficient to resolve the deferred.
    """
    __slots__ = ["deferred"]

    def __init__(self, deferred):
        self.deferred = deferred


class _NotifierUserStream(object):
    """This represents a user connected to the event stream.
    It tracks the most recent stream token for that user.
    At a given point a user may have a number of streams listening for
    events.

    This listener will also keep track of which rooms it is listening in
    so that it can remove itself from the indexes in the Notifier class.
    """

    def __init__(self, user_id, rooms, current_token, time_now_ms):
        self.user_id = user_id
        self.rooms = set(rooms)
        self.current_token = current_token

        # The last token for which we should wake up any streams that have a
        # token that comes before it. This gets updated everytime we get poked.
        # We start it at the current token since if we get any streams
        # that have a token from before we have no idea whether they should be
        # woken up or not, so lets just wake them up.
        self.last_notified_token = current_token
        self.last_notified_ms = time_now_ms

        with PreserveLoggingContext():
            self.notify_deferred = ObservableDeferred(defer.Deferred())

    def notify(self, stream_key, stream_id, time_now_ms):
        """Notify any listeners for this user of a new event from an
        event source.
        Args:
            stream_key(str): The stream the event came from.
            stream_id(str): The new id for the stream the event came from.
            time_now_ms(int): The current time in milliseconds.
        """
        self.current_token = self.current_token.copy_and_advance(
            stream_key, stream_id
        )
        self.last_notified_token = self.current_token
        self.last_notified_ms = time_now_ms
        noify_deferred = self.notify_deferred

        users_woken_by_stream_counter.labels(stream_key).inc()

        with PreserveLoggingContext():
            self.notify_deferred = ObservableDeferred(defer.Deferred())
            noify_deferred.callback(self.current_token)

    def remove(self, notifier):
        """ Remove this listener from all the indexes in the Notifier
        it knows about.
        """

        for room in self.rooms:
            lst = notifier.room_to_user_streams.get(room, set())
            lst.discard(self)

        notifier.user_to_user_stream.pop(self.user_id)

    def count_listeners(self):
        return len(self.notify_deferred.observers())

    def new_listener(self, token):
        """Returns a deferred that is resolved when there is a new token
        greater than the given token.

        Args:
            token: The token from which we are streaming from, i.e. we shouldn't
                notify for things that happened before this.
        """
        # Immediately wake up stream if something has already since happened
        # since their last token.
        if self.last_notified_token.is_after(token):
            return _NotificationListener(defer.succeed(self.current_token))
        else:
            return _NotificationListener(self.notify_deferred.observe())


class EventStreamResult(namedtuple("EventStreamResult", ("events", "tokens"))):
    def __nonzero__(self):
        return bool(self.events)
    __bool__ = __nonzero__  # python3


class Notifier(object):
    """ This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    UNUSED_STREAM_EXPIRY_MS = 10 * 60 * 1000

    def __init__(self, hs):
        self.user_to_user_stream = {}
        self.room_to_user_streams = {}

        self.hs = hs
        self.event_sources = hs.get_event_sources()
        self.store = hs.get_datastore()
        self.pending_new_room_events = []

        self.replication_callbacks = []

        self.clock = hs.get_clock()
        self.appservice_handler = hs.get_application_service_handler()

        if hs.should_send_federation():
            self.federation_sender = hs.get_federation_sender()
        else:
            self.federation_sender = None

        self.state_handler = hs.get_state_handler()

        self.clock.looping_call(
            self.remove_expired_streams, self.UNUSED_STREAM_EXPIRY_MS
        )

        self.replication_deferred = ObservableDeferred(defer.Deferred())

        # This is not a very cheap test to perform, but it's only executed
        # when rendering the metrics page, which is likely once per minute at
        # most when scraping it.
        def count_listeners():
            all_user_streams = set()

            for x in self.room_to_user_streams.values():
                all_user_streams |= x
            for x in self.user_to_user_stream.values():
                all_user_streams.add(x)

            return sum(stream.count_listeners() for stream in all_user_streams)
        LaterGauge("synapse_notifier_listeners", "", [], count_listeners)

        LaterGauge(
            "synapse_notifier_rooms", "", [],
            lambda: count(bool, self.room_to_user_streams.values()),
        )
        LaterGauge(
            "synapse_notifier_users", "", [],
            lambda: len(self.user_to_user_stream),
        )

    def add_replication_callback(self, cb):
        """Add a callback that will be called when some new data is available.
        Callback is not given any arguments.
        """
        self.replication_callbacks.append(cb)

    def on_new_room_event(self, event, room_stream_id, max_room_stream_id,
                          extra_users=[]):
        """ Used by handlers to inform the notifier something has happened
        in the room, room event wise.

        This triggers the notifier to wake up any listeners that are
        listening to the room, and any listeners for the users in the
        `extra_users` param.

        The events can be peristed out of order. The notifier will wait
        until all previous events have been persisted before notifying
        the client streams.
        """
        self.pending_new_room_events.append((
            room_stream_id, event, extra_users
        ))
        self._notify_pending_new_room_events(max_room_stream_id)

        self.notify_replication()

    def _notify_pending_new_room_events(self, max_room_stream_id):
        """Notify for the room events that were queued waiting for a previous
        event to be persisted.
        Args:
            max_room_stream_id(int): The highest stream_id below which all
                events have been persisted.
        """
        pending = self.pending_new_room_events
        self.pending_new_room_events = []
        for room_stream_id, event, extra_users in pending:
            if room_stream_id > max_room_stream_id:
                self.pending_new_room_events.append((
                    room_stream_id, event, extra_users
                ))
            else:
                self._on_new_room_event(event, room_stream_id, extra_users)

    def _on_new_room_event(self, event, room_stream_id, extra_users=[]):
        """Notify any user streams that are interested in this room event"""
        # poke any interested application service.
        run_in_background(self._notify_app_services, room_stream_id)

        if self.federation_sender:
            self.federation_sender.notify_new_events(room_stream_id)

        if event.type == EventTypes.Member and event.membership == Membership.JOIN:
            self._user_joined_room(event.state_key, event.room_id)

        self.on_new_event(
            "room_key", room_stream_id,
            users=extra_users,
            rooms=[event.room_id],
        )

    @defer.inlineCallbacks
    def _notify_app_services(self, room_stream_id):
        try:
            yield self.appservice_handler.notify_interested_services(room_stream_id)
        except Exception:
            logger.exception("Error notifying application services of event")

    def on_new_event(self, stream_key, new_token, users=[], rooms=[]):
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

    def on_new_replication_data(self):
        """Used to inform replication listeners that something has happend
        without waking up any of the normal user event streams"""
        self.notify_replication()

    @defer.inlineCallbacks
    def wait_for_events(self, user_id, timeout, callback, room_ids=None,
                        from_token=StreamToken.START):
        """Wait until the callback returns a non empty response or the
        timeout fires.
        """
        user_stream = self.user_to_user_stream.get(user_id)
        if user_stream is None:
            current_token = yield self.event_sources.get_current_token()
            if room_ids is None:
                room_ids = yield self.store.get_rooms_for_user(user_id)
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
                    add_timeout_to_deferred(
                        listener.deferred,
                        (end_time - now) / 1000.,
                        self.hs.get_reactor(),
                    )
                    with PreserveLoggingContext():
                        yield listener.deferred

                    current_token = user_stream.current_token

                    result = yield callback(prev_token, current_token)
                    if result:
                        break

                    # Update the prev_token to the current_token since nothing
                    # has happened between the old prev_token and the current_token
                    prev_token = current_token
                except DeferredTimeoutError:
                    break
                except defer.CancelledError:
                    break

        if result is None:
            # This happened if there was no timeout or if the timeout had
            # already expired.
            current_token = user_stream.current_token
            result = yield callback(prev_token, current_token)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def get_events_for(self, user, pagination_config, timeout,
                       only_keys=None,
                       is_guest=False, explicit_room_id=None):
        """ For the given user and rooms, return any new events for them. If
        there are no new events wait for up to `timeout` milliseconds for any
        new events to happen before returning.

        If `only_keys` is not None, events from keys will be sent down.

        If explicit_room_id is not set, the user's joined rooms will be polled
        for events.
        If explicit_room_id is set, that room will be polled for events only if
        it is world readable or the user has joined the room.
        """
        from_token = pagination_config.from_token
        if not from_token:
            from_token = yield self.event_sources.get_current_token()

        limit = pagination_config.limit

        room_ids, is_joined = yield self._get_room_ids(user, explicit_room_id)
        is_peeking = not is_joined

        @defer.inlineCallbacks
        def check_for_updates(before_token, after_token):
            if not after_token.is_after(before_token):
                defer.returnValue(EventStreamResult([], (from_token, from_token)))

            events = []
            end_token = from_token

            for name, source in self.event_sources.sources.items():
                keyname = "%s_key" % name
                before_id = getattr(before_token, keyname)
                after_id = getattr(after_token, keyname)
                if before_id == after_id:
                    continue
                if only_keys and name not in only_keys:
                    continue

                new_events, new_key = yield source.get_new_events(
                    user=user,
                    from_key=getattr(from_token, keyname),
                    limit=limit,
                    is_guest=is_peeking,
                    room_ids=room_ids,
                    explicit_room_id=explicit_room_id,
                )

                if name == "room":
                    new_events = yield filter_events_for_client(
                        self.store,
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

            defer.returnValue(EventStreamResult(events, (from_token, end_token)))

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
                explicit_room_id, user_id_for_stream
            )

        result = yield self.wait_for_events(
            user_id_for_stream,
            timeout,
            check_for_updates,
            room_ids=room_ids,
            from_token=from_token,
        )

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _get_room_ids(self, user, explicit_room_id):
        joined_room_ids = yield self.store.get_rooms_for_user(user.to_string())
        if explicit_room_id:
            if explicit_room_id in joined_room_ids:
                defer.returnValue(([explicit_room_id], True))
            if (yield self._is_world_readable(explicit_room_id)):
                defer.returnValue(([explicit_room_id], False))
            raise AuthError(403, "Non-joined access not allowed")
        defer.returnValue((joined_room_ids, True))

    @defer.inlineCallbacks
    def _is_world_readable(self, room_id):
        state = yield self.state_handler.get_current_state(
            room_id,
            EventTypes.RoomHistoryVisibility,
            "",
        )
        if state and "history_visibility" in state.content:
            defer.returnValue(state.content["history_visibility"] == "world_readable")
        else:
            defer.returnValue(False)

    @log_function
    def remove_expired_streams(self):
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
    def _register_with_keys(self, user_stream):
        self.user_to_user_stream[user_stream.user_id] = user_stream

        for room in user_stream.rooms:
            s = self.room_to_user_streams.setdefault(room, set())
            s.add(user_stream)

    def _user_joined_room(self, user_id, room_id):
        new_user_stream = self.user_to_user_stream.get(user_id)
        if new_user_stream is not None:
            room_streams = self.room_to_user_streams.setdefault(room_id, set())
            room_streams.add(new_user_stream)
            new_user_stream.rooms.add(room_id)

    def notify_replication(self):
        """Notify the any replication listeners that there's a new event"""
        with PreserveLoggingContext():
            deferred = self.replication_deferred
            self.replication_deferred = ObservableDeferred(defer.Deferred())
            deferred.callback(None)

            # the callbacks may well outlast the current request, so we run
            # them in the sentinel logcontext.
            #
            # (ideally it would be up to the callbacks to know if they were
            # starting off background processes and drop the logcontext
            # accordingly, but that requires more changes)
            for cb in self.replication_callbacks:
                cb()

    @defer.inlineCallbacks
    def wait_for_replication(self, callback, timeout):
        """Wait for an event to happen.

        Args:
            callback: Gets called whenever an event happens. If this returns a
                truthy value then ``wait_for_replication`` returns, otherwise
                it waits for another event.
            timeout: How many milliseconds to wait for callback return a truthy
                value.

        Returns:
            A deferred that resolves with the value returned by the callback.
        """
        listener = _NotificationListener(None)

        end_time = self.clock.time_msec() + timeout

        while True:
            listener.deferred = self.replication_deferred.observe()
            result = yield callback()
            if result:
                break

            now = self.clock.time_msec()
            if end_time <= now:
                break

            add_timeout_to_deferred(
                listener.deferred.addTimeout,
                (end_time - now) / 1000.,
                self.hs.get_reactor(),
            )
            try:
                with PreserveLoggingContext():
                    yield listener.deferred
            except DeferredTimeoutError:
                break
            except defer.CancelledError:
                break

        defer.returnValue(result)
