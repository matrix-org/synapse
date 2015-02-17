# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.util.logutils import log_function
from synapse.util.logcontext import PreserveLoggingContext
from synapse.util.async import run_on_reactor
from synapse.types import StreamToken

import logging


logger = logging.getLogger(__name__)


class _NotificationListener(object):
    """ This represents a single client connection to the events stream.

    The events stream handler will have yielded to the deferred, so to
    notify the handler it is sufficient to resolve the deferred.

    This listener will also keep track of which rooms it is listening in
    so that it can remove itself from the indexes in the Notifier class.
    """

    def __init__(self, user, rooms, from_token, limit, timeout, deferred):
        self.user = user
        self.from_token = from_token
        self.limit = limit
        self.timeout = timeout
        self.deferred = deferred

        self.rooms = rooms

        self.pending_notifications = []

    def notify(self, notifier, events, start_token, end_token):
        """ Inform whoever is listening about the new events. This will
        also remove this listener from all the indexes in the Notifier
        it knows about.
        """

        result = (events, (start_token, end_token))

        try:
            self.deferred.callback(result)
        except defer.AlreadyCalledError:
            pass

        for room in self.rooms:
            lst = notifier.rooms_to_listeners.get(room, set())
            lst.discard(self)

        notifier.user_to_listeners.get(self.user, set()).discard(self)


class Notifier(object):
    """ This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    def __init__(self, hs):
        self.hs = hs

        self.rooms_to_listeners = {}
        self.user_to_listeners = {}

        self.event_sources = hs.get_event_sources()

        self.clock = hs.get_clock()

        hs.get_distributor().observe(
            "user_joined_room", self._user_joined_room
        )

    @log_function
    @defer.inlineCallbacks
    def on_new_room_event(self, event, extra_users=[]):
        """ Used by handlers to inform the notifier something has happened
        in the room, room event wise.

        This triggers the notifier to wake up any listeners that are
        listening to the room, and any listeners for the users in the
        `extra_users` param.
        """
        yield run_on_reactor()

        # poke any interested application service.
        self.hs.get_handlers().appservice_handler.notify_interested_services(
            event
        )

        room_id = event.room_id

        room_source = self.event_sources.sources["room"]

        listeners = self.rooms_to_listeners.get(room_id, set()).copy()

        for user in extra_users:
            listeners |= self.user_to_listeners.get(user, set()).copy()

        logger.debug("on_new_room_event listeners %s", listeners)

        # TODO (erikj): Can we make this more efficient by hitting the
        # db once?

        @defer.inlineCallbacks
        def notify(listener):
            events, end_key = yield room_source.get_new_events_for_user(
                listener.user,
                listener.from_token.room_key,
                listener.limit,
            )

            if events:
                end_token = listener.from_token.copy_and_replace(
                    "room_key", end_key
                )

                listener.notify(
                    self, events, listener.from_token, end_token
                )

        def eb(failure):
            logger.exception("Failed to notify listener", failure)

        with PreserveLoggingContext():
            yield defer.DeferredList(
                [notify(l).addErrback(eb) for l in listeners],
                consumeErrors=True,
            )

    @defer.inlineCallbacks
    @log_function
    def on_new_user_event(self, users=[], rooms=[]):
        """ Used to inform listeners that something has happend
        presence/user event wise.

        Will wake up all listeners for the given users and rooms.
        """
        yield run_on_reactor()

        # TODO(paul): This is horrible, having to manually list every event
        # source here individually
        presence_source = self.event_sources.sources["presence"]
        typing_source = self.event_sources.sources["typing"]

        listeners = set()

        for user in users:
            listeners |= self.user_to_listeners.get(user, set()).copy()

        for room in rooms:
            listeners |= self.rooms_to_listeners.get(room, set()).copy()

        @defer.inlineCallbacks
        def notify(listener):
            presence_events, presence_end_key = (
                yield presence_source.get_new_events_for_user(
                    listener.user,
                    listener.from_token.presence_key,
                    listener.limit,
                )
            )
            typing_events, typing_end_key = (
                yield typing_source.get_new_events_for_user(
                    listener.user,
                    listener.from_token.typing_key,
                    listener.limit,
                )
            )

            if presence_events or typing_events:
                end_token = listener.from_token.copy_and_replace(
                    "presence_key", presence_end_key
                ).copy_and_replace(
                    "typing_key", typing_end_key
                )

                listener.notify(
                    self,
                    presence_events + typing_events,
                    listener.from_token,
                    end_token
                )

        def eb(failure):
            logger.error(
                "Failed to notify listener",
                exc_info=(
                    failure.type,
                    failure.value,
                    failure.getTracebackObject())
            )

        with PreserveLoggingContext():
            yield defer.DeferredList(
                [notify(l).addErrback(eb) for l in listeners],
                consumeErrors=True,
            )

    @defer.inlineCallbacks
    def wait_for_events(self, user, rooms, filter, timeout, callback):
        """Wait until the callback returns a non empty response or the
        timeout fires.
        """

        deferred = defer.Deferred()

        from_token = StreamToken("s0", "0", "0")

        listener = [_NotificationListener(
            user=user,
            rooms=rooms,
            from_token=from_token,
            limit=1,
            timeout=timeout,
            deferred=deferred,
        )]

        if timeout:
            self._register_with_keys(listener[0])

        result = yield callback()
        if timeout:
            timed_out = [False]

            def _timeout_listener():
                timed_out[0] = True
                listener[0].notify(self, [], from_token, from_token)

            self.clock.call_later(timeout/1000., _timeout_listener)
            while not result and not timed_out[0]:
                yield deferred
                deferred = defer.Deferred()
                listener[0] = _NotificationListener(
                    user=user,
                    rooms=rooms,
                    from_token=from_token,
                    limit=1,
                    timeout=timeout,
                    deferred=deferred,
                )
                self._register_with_keys(listener[0])
                result = yield callback()

        defer.returnValue(result)

    def get_events_for(self, user, rooms, pagination_config, timeout):
        """ For the given user and rooms, return any new events for them. If
        there are no new events wait for up to `timeout` milliseconds for any
        new events to happen before returning.
        """
        deferred = defer.Deferred()

        self._get_events(
            deferred, user, rooms, pagination_config.from_token,
            pagination_config.limit, timeout
        ).addErrback(deferred.errback)

        return deferred

    @defer.inlineCallbacks
    def _get_events(self, deferred, user, rooms, from_token, limit, timeout):
        if not from_token:
            from_token = yield self.event_sources.get_current_token()

        listener = _NotificationListener(
            user,
            rooms,
            from_token,
            limit,
            timeout,
            deferred,
        )

        def _timeout_listener():
            # TODO (erikj): We should probably set to_token to the current
            # max rather than reusing from_token.
            listener.notify(
                self,
                [],
                listener.from_token,
                listener.from_token,
            )

        if timeout:
            self._register_with_keys(listener)

        yield self._check_for_updates(listener)

        if not timeout:
            _timeout_listener()
        else:
            self.clock.call_later(timeout/1000.0, _timeout_listener)

        return

    @log_function
    def _register_with_keys(self, listener):
        for room in listener.rooms:
            s = self.rooms_to_listeners.setdefault(room, set())
            s.add(listener)

        self.user_to_listeners.setdefault(listener.user, set()).add(listener)

    @defer.inlineCallbacks
    @log_function
    def _check_for_updates(self, listener):
        # TODO (erikj): We need to think about limits across multiple sources
        events = []

        from_token = listener.from_token
        limit = listener.limit

        # TODO (erikj): DeferredList?
        for name, source in self.event_sources.sources.items():
            keyname = "%s_key" % name

            stuff, new_key = yield source.get_new_events_for_user(
                listener.user,
                getattr(from_token, keyname),
                limit,
            )

            events.extend(stuff)

            from_token = from_token.copy_and_replace(keyname, new_key)

        end_token = from_token

        if events:
            listener.notify(self, events, listener.from_token, end_token)

        defer.returnValue(listener)

    def _user_joined_room(self, user, room_id):
        new_listeners = self.user_to_listeners.get(user, set())

        listeners = self.rooms_to_listeners.setdefault(room_id, set())
        listeners |= new_listeners
