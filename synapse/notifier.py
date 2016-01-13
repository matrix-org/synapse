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

from twisted.internet import defer
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError

from synapse.util.logutils import log_function
from synapse.util.async import run_on_reactor, ObservableDeferred
from synapse.types import StreamToken
import synapse.metrics

import logging


logger = logging.getLogger(__name__)

metrics = synapse.metrics.get_metrics_for(__name__)

notified_events_counter = metrics.register_counter("notified_events")


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

    def __init__(self, user, rooms, current_token, time_now_ms,
                 appservice=None):
        self.user = str(user)
        self.appservice = appservice
        self.rooms = set(rooms)
        self.current_token = current_token
        self.last_notified_ms = time_now_ms

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
        self.last_notified_ms = time_now_ms
        noify_deferred = self.notify_deferred
        self.notify_deferred = ObservableDeferred(defer.Deferred())
        noify_deferred.callback(self.current_token)

    def remove(self, notifier):
        """ Remove this listener from all the indexes in the Notifier
        it knows about.
        """

        for room in self.rooms:
            lst = notifier.room_to_user_streams.get(room, set())
            lst.discard(self)

        notifier.user_to_user_stream.pop(self.user)

        if self.appservice:
            notifier.appservice_to_user_streams.get(
                self.appservice, set()
            ).discard(self)

    def count_listeners(self):
        return len(self.notify_deferred.observers())

    def new_listener(self, token):
        """Returns a deferred that is resolved when there is a new token
        greater than the given token.
        """
        if self.current_token.is_after(token):
            return _NotificationListener(defer.succeed(self.current_token))
        else:
            return _NotificationListener(self.notify_deferred.observe())


class Notifier(object):
    """ This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    UNUSED_STREAM_EXPIRY_MS = 10 * 60 * 1000

    def __init__(self, hs):
        self.hs = hs

        self.user_to_user_stream = {}
        self.room_to_user_streams = {}
        self.appservice_to_user_streams = {}

        self.event_sources = hs.get_event_sources()
        self.store = hs.get_datastore()
        self.pending_new_room_events = []

        self.clock = hs.get_clock()

        hs.get_distributor().observe(
            "user_joined_room", self._user_joined_room
        )

        self.clock.looping_call(
            self.remove_expired_streams, self.UNUSED_STREAM_EXPIRY_MS
        )

        # This is not a very cheap test to perform, but it's only executed
        # when rendering the metrics page, which is likely once per minute at
        # most when scraping it.
        def count_listeners():
            all_user_streams = set()

            for x in self.room_to_user_streams.values():
                all_user_streams |= x
            for x in self.user_to_user_stream.values():
                all_user_streams.add(x)
            for x in self.appservice_to_user_streams.values():
                all_user_streams |= x

            return sum(stream.count_listeners() for stream in all_user_streams)
        metrics.register_callback("listeners", count_listeners)

        metrics.register_callback(
            "rooms",
            lambda: count(bool, self.room_to_user_streams.values()),
        )
        metrics.register_callback(
            "users",
            lambda: len(self.user_to_user_stream),
        )
        metrics.register_callback(
            "appservices",
            lambda: count(bool, self.appservice_to_user_streams.values()),
        )

    @log_function
    @defer.inlineCallbacks
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
        yield run_on_reactor()

        self.pending_new_room_events.append((
            room_stream_id, event, extra_users
        ))
        self._notify_pending_new_room_events(max_room_stream_id)

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
        self.hs.get_handlers().appservice_handler.notify_interested_services(
            event
        )

        app_streams = set()

        for appservice in self.appservice_to_user_streams:
            # TODO (kegan): Redundant appservice listener checks?
            # App services will already be in the room_to_user_streams set, but
            # that isn't enough. They need to be checked here in order to
            # receive *invites* for users they are interested in. Does this
            # make the room_to_user_streams check somewhat obselete?
            if appservice.is_interested(event):
                app_user_streams = self.appservice_to_user_streams.get(
                    appservice, set()
                )
                app_streams |= app_user_streams

        self.on_new_event(
            "room_key", room_stream_id,
            users=extra_users,
            rooms=[event.room_id],
            extra_streams=app_streams,
        )

    @defer.inlineCallbacks
    @log_function
    def on_new_event(self, stream_key, new_token, users=[], rooms=[],
                     extra_streams=set()):
        """ Used to inform listeners that something has happend event wise.

        Will wake up all listeners for the given users and rooms.
        """
        yield run_on_reactor()
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
            except:
                logger.exception("Failed to notify listener")

    @defer.inlineCallbacks
    def wait_for_events(self, user, timeout, callback, room_ids=None,
                        from_token=StreamToken("s0", "0", "0", "0", "0")):
        """Wait until the callback returns a non empty response or the
        timeout fires.
        """
        user = str(user)
        user_stream = self.user_to_user_stream.get(user)
        if user_stream is None:
            appservice = self.store.get_app_service_by_user_id(user)
            current_token = yield self.event_sources.get_current_token()
            if room_ids is None:
                rooms = yield self.store.get_rooms_for_user(user)
                room_ids = [room.room_id for room in rooms]
            user_stream = _NotifierUserStream(
                user=user,
                rooms=room_ids,
                appservice=appservice,
                current_token=current_token,
                time_now_ms=self.clock.time_msec(),
            )
            self._register_with_keys(user_stream)

        result = None
        if timeout:
            # Will be set to a _NotificationListener that we'll be waiting on.
            # Allows us to cancel it.
            listener = None

            def timed_out():
                if listener:
                    listener.deferred.cancel()
            timer = self.clock.call_later(timeout/1000., timed_out)

            prev_token = from_token
            while not result:
                try:
                    current_token = user_stream.current_token

                    result = yield callback(prev_token, current_token)
                    if result:
                        break

                    # Now we wait for the _NotifierUserStream to be told there
                    # is a new token.
                    # We need to supply the token we supplied to callback so
                    # that we don't miss any current_token updates.
                    prev_token = current_token
                    listener = user_stream.new_listener(prev_token)
                    yield listener.deferred
                except defer.CancelledError:
                    break

            self.clock.cancel_call_later(timer, ignore_errs=True)
        else:
            current_token = user_stream.current_token
            result = yield callback(from_token, current_token)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def get_events_for(self, user, pagination_config, timeout,
                       only_room_events=False,
                       is_guest=False, guest_room_id=None):
        """ For the given user and rooms, return any new events for them. If
        there are no new events wait for up to `timeout` milliseconds for any
        new events to happen before returning.

        If `only_room_events` is `True` only room events will be returned.
        """
        from_token = pagination_config.from_token
        if not from_token:
            from_token = yield self.event_sources.get_current_token()

        limit = pagination_config.limit

        room_ids = []
        if is_guest:
            if guest_room_id:
                if not (yield self._is_world_readable(guest_room_id)):
                    raise AuthError(403, "Guest access not allowed")
                room_ids = [guest_room_id]
        else:
            rooms = yield self.store.get_rooms_for_user(user.to_string())
            room_ids = [room.room_id for room in rooms]

        @defer.inlineCallbacks
        def check_for_updates(before_token, after_token):
            if not after_token.is_after(before_token):
                defer.returnValue(None)

            events = []
            end_token = from_token

            for name, source in self.event_sources.sources.items():
                keyname = "%s_key" % name
                before_id = getattr(before_token, keyname)
                after_id = getattr(after_token, keyname)
                if before_id == after_id:
                    continue
                if only_room_events and name != "room":
                    continue
                new_events, new_key = yield source.get_new_events(
                    user=user,
                    from_key=getattr(from_token, keyname),
                    limit=limit,
                    is_guest=is_guest,
                    room_ids=room_ids,
                )

                if name == "room":
                    room_member_handler = self.hs.get_handlers().room_member_handler
                    new_events = yield room_member_handler._filter_events_for_client(
                        user.to_string(),
                        new_events,
                        is_guest=is_guest,
                    )

                events.extend(new_events)
                end_token = end_token.copy_and_replace(keyname, new_key)

            if events:
                defer.returnValue((events, (from_token, end_token)))
            else:
                defer.returnValue(None)

        result = yield self.wait_for_events(
            user, timeout, check_for_updates, room_ids=room_ids, from_token=from_token
        )

        if result is None:
            result = ([], (from_token, from_token))

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _is_world_readable(self, room_id):
        state = yield self.hs.get_state_handler().get_current_state(
            room_id,
            EventTypes.RoomHistoryVisibility
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
        self.user_to_user_stream[user_stream.user] = user_stream

        for room in user_stream.rooms:
            s = self.room_to_user_streams.setdefault(room, set())
            s.add(user_stream)

        if user_stream.appservice:
            self.appservice_to_user_stream.setdefault(
                user_stream.appservice, set()
            ).add(user_stream)

    def _user_joined_room(self, user, room_id):
        user = str(user)
        new_user_stream = self.user_to_user_stream.get(user)
        if new_user_stream is not None:
            room_streams = self.room_to_user_streams.setdefault(room_id, set())
            room_streams.add(new_user_stream)
            new_user_stream.rooms.add(room_id)
