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

    def __init__(self, deferred):
        self.deferred = deferred

    def notified(self):
        return self.deferred.called

    def notify(self):
        """ Inform whoever is listening about the new events.
        """

        try:
            self.deferred.callback(None)
        except defer.AlreadyCalledError:
            pass


class _NotifierUserStream(object):
    """This represents a user connected to the event stream.
    It tracks the most recent stream token for that user.
    At a given point a user may have a number of streams listening for
    events.

    This listener will also keep track of which rooms it is listening in
    so that it can remove itself from the indexes in the Notifier class.
    """

    def __init__(self, user, rooms, current_token, appservice=None):
        self.user = user
        self.appservice = appservice
        self.listeners = set()
        self.rooms = rooms
        self.current_token = current_token

    def notify(self, new_token):
        for listener in self.listeners:
            listener.notify(new_token)
        self.listeners.clear()

    def remove(self, notifier):
        """ Remove this listener from all the indexes in the Notifier
        it knows about.
        """

        for room in self.rooms:
            lst = notifier.room_to_user_streams.get(room, set())
            lst.discard(self)

        notifier.user_to_user_streams.get(self.user, set()).discard(self)

        if self.appservice:
            notifier.appservice_to_user_streams.get(
                self.appservice, set()
            ).discard(self)


class Notifier(object):
    """ This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    def __init__(self, hs):
        self.hs = hs

        self.user_to_user_stream = {}
        self.room_to_user_streams = {}
        self.appservice_to_user_streams = {}

        self.event_sources = hs.get_event_sources()
        self.store = hs.get_datastore()

        self.clock = hs.get_clock()

        hs.get_distributor().observe(
            "user_joined_room", self._user_joined_room
        )

        # This is not a very cheap test to perform, but it's only executed
        # when rendering the metrics page, which is likely once per minute at
        # most when scraping it.
        def count_listeners():
            all_user_streams = set()

            for x in self.room_to_user_streams.values():
                all_user_streams |= x
            for x in self.user_to_user_streams.values():
                all_user_streams |= x
            for x in self.appservice_to_user_streams.values():
                all_user_streams |= x

            return sum(len(stream.listeners) for stream in all_user_streams)
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
    def on_new_room_event(self, event, new_token, extra_users=[]):
        """ Used by handlers to inform the notifier something has happened
        in the room, room event wise.

        This triggers the notifier to wake up any listeners that are
        listening to the room, and any listeners for the users in the
        `extra_users` param.
        """
        assert isinstance(new_token, StreamToken)
        yield run_on_reactor()
        # poke any interested application service.
        self.hs.get_handlers().appservice_handler.notify_interested_services(
            event
        )

        room_id = event.room_id

        room_user_streams = self.room_to_user_streams.get(room_id, set())

        user_streams = room_user_streams.copy()

        for user in extra_users:
            user_stream = self.user_to_user_stream.get(user)
            if user_stream is not None:
                user_streams.add(user_stream)

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
                user_streams |= app_user_streams

        logger.debug("on_new_room_event listeners %s", user_streams)

        with PreserveLoggingContext():
            for user_stream in user_streams:
                try:
                    user_stream.notify(new_token)
                except:
                    logger.exception("Failed to notify listener")

    @defer.inlineCallbacks
    @log_function
    def on_new_user_event(self, new_token, users=[], rooms=[]):
        """ Used to inform listeners that something has happend
        presence/user event wise.

        Will wake up all listeners for the given users and rooms.
        """
        assert isinstance(new_token, StreamToken)
        yield run_on_reactor()
        user_streams = set()

        for user in users:
            user_stream = self.user_to_user_stream.get(user)
            if user_stream:
                user_stream.add(user_stream)

        for room in rooms:
            user_streams |= self.room_to_user_streams.get(room, set())

        with PreserveLoggingContext():
            for user_stream in user_streams:
                try:
                    user_streams.notify(new_token)
                except:
                    logger.exception("Failed to notify listener")

    @defer.inlineCallbacks
    def wait_for_events(self, user, rooms, timeout, callback,
                        from_token=StreamToken("s0", "0", "0")):
        """Wait until the callback returns a non empty response or the
        timeout fires.
        """

        deferred = defer.Deferred()

        user_stream = self.user_to_user_streams.get(user)
        if user_stream is None:
            appservice = yield self.store.get_app_service_by_user_id(
                user.to_string()
            )
            current_token = yield self.event_sources.get_current_token()
            user_stream = _NotifierUserStream(
                user=user,
                rooms=rooms,
                appservice=appservice,
                current_token=current_token,
            )
            self._register_with_keys(user_stream)
        else:
            current_token = user_stream.current_token

        if timeout and not current_token.is_after(from_token):
            listener = [_NotificationListener(deferred)]
            user_stream.listeners.add(listener[0])

        if current_token.is_after(from_token):
            result = yield callback(from_token, current_token)
        else:
            result = None

        timer = [None]

        if timeout:
            timed_out = [False]

            def _timeout_listener():
                timed_out[0] = True
                timer[0] = None
                listener[0].notify(user_stream)

            # We create multiple notification listeners so we have to manage
            # canceling the timeout ourselves.
            timer[0] = self.clock.call_later(timeout/1000., _timeout_listener)

            while not result and not timed_out[0]:
                new_token = yield deferred
                deferred = defer.Deferred()
                listener[0] = _NotificationListener(deferred)
                user_stream.listeners.add(listener[0])
                result = yield callback(current_token, new_token)
                current_token = new_token

        if timer[0] is not None:
            try:
                self.clock.cancel_call_later(timer[0])
            except:
                logger.exception("Failed to cancel notifer timer")

        defer.returnValue(result)

    @defer.inlineCallbacks
    def get_events_for(self, user, rooms, pagination_config, timeout):
        """ For the given user and rooms, return any new events for them. If
        there are no new events wait for up to `timeout` milliseconds for any
        new events to happen before returning.
        """
        from_token = pagination_config.from_token
        if not from_token:
            from_token = yield self.event_sources.get_current_token()

        limit = pagination_config.limit

        @defer.inlineCallbacks
        def check_for_updates(start_token, end_token):
            events = []
            end_token = from_token
            for name, source in self.event_sources.sources.items():
                keyname = "%s_key" % name
                stuff, new_key = yield source.get_new_events_for_user(
                    user, getattr(from_token, keyname), limit,
                )
                events.extend(stuff)
                end_token = from_token.copy_and_replace(keyname, new_key)

            if events:
                defer.returnValue((events, (from_token, end_token)))
            else:
                defer.returnValue(None)

        result = yield self.wait_for_events(
            user, rooms, timeout, check_for_updates, from_token=from_token
        )

        if result is None:
            result = ([], (from_token, from_token))

        defer.returnValue(result)

    @log_function
    def _register_with_keys(self, user_stream):
        self.user_to_user_stream[user_stream.user] = user_stream

        for room in user_stream.rooms:
            s = self.room_to_user_stream.setdefault(room, set())
            s.add(user_stream)

        if user_stream.appservice:
            self.appservice_to_user_stream.setdefault(
                user_stream.appservice, set()
            ).add(user_stream)

    def _user_joined_room(self, user, room_id):
        new_user_stream = self.user_to_user_stream.get(user)
        room_streams = self.room_to_user_streams.setdefault(room_id, set())
        room_streams.add(new_user_stream)
        new_user_stream.rooms.add(room_id)


def _discard_if_notified(listener_set):
    """Remove any 'stale' listeners from the given set.
    """
    to_discard = set()
    for l in listener_set:
        if l.notified():
            to_discard.add(l)

    listener_set -= to_discard
