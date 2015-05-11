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

    This listener will also keep track of which rooms it is listening in
    so that it can remove itself from the indexes in the Notifier class.
    """

    def __init__(self, user, rooms, deferred, appservice=None):
        self.user = user
        self.appservice = appservice
        self.deferred = deferred
        self.rooms = rooms
        self.timer = None

    def notified(self):
        return self.deferred.called

    def notify(self, notifier):
        """ Inform whoever is listening about the new events. This will
        also remove this listener from all the indexes in the Notifier
        it knows about.
        """

        try:
            self.deferred.callback(None)
        except defer.AlreadyCalledError:
            pass

        # Should the following be done be using intrusively linked lists?
        # -- erikj

        for room in self.rooms:
            lst = notifier.room_to_listeners.get(room, set())
            lst.discard(self)

        notifier.user_to_listeners.get(self.user, set()).discard(self)

        if self.appservice:
            notifier.appservice_to_listeners.get(
                self.appservice, set()
            ).discard(self)

        # Cancel the timeout for this notifer if one exists.
        if self.timer is not None:
            try:
                notifier.clock.cancel_call_later(self.timer)
            except:
                logger.warn("Failed to cancel notifier timer")


class Notifier(object):
    """ This class is responsible for notifying any listeners when there are
    new events available for it.

    Primarily used from the /events stream.
    """

    def __init__(self, hs):
        self.hs = hs

        self.room_to_listeners = {}
        self.user_to_listeners = {}
        self.appservice_to_listeners = {}

        self.event_sources = hs.get_event_sources()

        self.clock = hs.get_clock()

        hs.get_distributor().observe(
            "user_joined_room", self._user_joined_room
        )

        # This is not a very cheap test to perform, but it's only executed
        # when rendering the metrics page, which is likely once per minute at
        # most when scraping it.
        def count_listeners():
            all_listeners = set()

            for x in self.room_to_listeners.values():
                all_listeners |= x
            for x in self.user_to_listeners.values():
                all_listeners |= x
            for x in self.appservice_to_listeners.values():
                all_listeners |= x

            return len(all_listeners)
        metrics.register_callback("listeners", count_listeners)

        metrics.register_callback(
            "rooms",
            lambda: count(bool, self.room_to_listeners.values()),
        )
        metrics.register_callback(
            "users",
            lambda: count(bool, self.user_to_listeners.values()),
        )
        metrics.register_callback(
            "appservices",
            lambda: count(bool, self.appservice_to_listeners.values()),
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

        room_listeners = self.room_to_listeners.get(room_id, set())

        _discard_if_notified(room_listeners)

        listeners = room_listeners.copy()

        for user in extra_users:
            user_listeners = self.user_to_listeners.get(user, set())

            _discard_if_notified(user_listeners)

            listeners |= user_listeners

        for appservice in self.appservice_to_listeners:
            # TODO (kegan): Redundant appservice listener checks?
            # App services will already be in the room_to_listeners set, but
            # that isn't enough. They need to be checked here in order to
            # receive *invites* for users they are interested in. Does this
            # make the room_to_listeners check somewhat obselete?
            if appservice.is_interested(event):
                app_listeners = self.appservice_to_listeners.get(
                    appservice, set()
                )

                _discard_if_notified(app_listeners)

                listeners |= app_listeners

        logger.debug("on_new_room_event listeners %s", listeners)

        with PreserveLoggingContext():
            for listener in listeners:
                try:
                    listener.notify(self)
                except:
                    logger.exception("Failed to notify listener")

    @defer.inlineCallbacks
    @log_function
    def on_new_user_event(self, users=[], rooms=[]):
        """ Used to inform listeners that something has happend
        presence/user event wise.

        Will wake up all listeners for the given users and rooms.
        """
        yield run_on_reactor()
        listeners = set()

        for user in users:
            user_listeners = self.user_to_listeners.get(user, set())

            _discard_if_notified(user_listeners)

            listeners |= user_listeners

        for room in rooms:
            room_listeners = self.room_to_listeners.get(room, set())

            _discard_if_notified(room_listeners)

            listeners |= room_listeners

        with PreserveLoggingContext():
            for listener in listeners:
                try:
                    listener.notify(self)
                except:
                    logger.exception("Failed to notify listener")

    @defer.inlineCallbacks
    def wait_for_events(self, user, rooms, timeout, callback,
                        from_token=StreamToken("s0", "0", "0")):
        """Wait until the callback returns a non empty response or the
        timeout fires.
        """

        deferred = defer.Deferred()
        appservice = yield self.hs.get_datastore().get_app_service_by_user_id(
            user.to_string()
        )

        listener = [_NotificationListener(
            user=user,
            rooms=rooms,
            deferred=deferred,
            appservice=appservice,
        )]

        if timeout:
            self._register_with_keys(listener[0])

        result = yield callback()
        timer = [None]

        if timeout:
            timed_out = [False]

            def _timeout_listener():
                timed_out[0] = True
                timer[0] = None
                listener[0].notify(self)

            # We create multiple notification listeners so we have to manage
            # canceling the timeout ourselves.
            timer[0] = self.clock.call_later(timeout/1000., _timeout_listener)

            while not result and not timed_out[0]:
                yield deferred
                deferred = defer.Deferred()
                listener[0] = _NotificationListener(
                    user=user,
                    rooms=rooms,
                    deferred=deferred,
                    appservice=appservice,
                )
                self._register_with_keys(listener[0])
                result = yield callback()

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
        def check_for_updates():
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
    def _register_with_keys(self, listener):
        for room in listener.rooms:
            s = self.room_to_listeners.setdefault(room, set())
            s.add(listener)

        self.user_to_listeners.setdefault(listener.user, set()).add(listener)

        if listener.appservice:
            self.appservice_to_listeners.setdefault(
                listener.appservice, set()
            ).add(listener)

    def _user_joined_room(self, user, room_id):
        new_listeners = self.user_to_listeners.get(user, set())

        listeners = self.room_to_listeners.setdefault(room_id, set())
        listeners |= new_listeners

        for l in new_listeners:
            l.rooms.add(room_id)


def _discard_if_notified(listener_set):
    """Remove any 'stale' listeners from the given set.
    """
    to_discard = set()
    for l in listener_set:
        if l.notified():
            to_discard.add(l)

    listener_set -= to_discard
