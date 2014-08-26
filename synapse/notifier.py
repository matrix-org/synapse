# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from twisted.internet import defer, reactor

from synapse.util.logutils import log_function

import logging


logger = logging.getLogger(__name__)


class _NotificationListener(object):
    def __init__(self, user, from_token, limit, timeout, deferred):
        self.user = user
        self.from_token = from_token
        self.limit = limit
        self.timeout = timeout
        self.deferred = deferred

        self.signal_key_list = []

        self.pending_notifications = []

    def notify(self, notifier, events, start_token, end_token):
        result = (events, (start_token, end_token))

        try:
            self.deferred.callback(result)
        except defer.AlreadyCalledError:
            pass

        for signal, key in self.signal_key_list:
            lst = notifier.signal_keys_to_users.get((signal, key), [])

            try:
                lst.remove(self)
            except:
                pass

class Notifier(object):

    def __init__(self, hs):
        self.hs = hs

        self.signal_keys_to_users = {}

        self.event_sources = hs.get_event_sources()

    @log_function
    @defer.inlineCallbacks
    def on_new_room_event(self, event, store_id):
        room_id = event.room_id

        source = self.event_sources.sources[0]

        listeners = self.signal_keys_to_users.get(
            (source.SIGNAL_NAME, room_id),
            []
        )

        logger.debug("on_new_room_event self.signal_keys_to_users %s", listeners)
        logger.debug("on_new_room_event listeners %s", listeners)

        # TODO (erikj): Can we make this more efficient by hitting the
        # db once?
        for listener in listeners:
            events, end_token = yield source.get_new_events_for_user(
                listener.user,
                listener.from_token,
                listener.limit,
                key=room_id,
            )

            if events:
                listener.notify(
                    self, events, listener.from_token, end_token
                )

    def on_new_user_event(self, *args, **kwargs):
        pass

    def get_events_for(self, user, pagination_config, timeout):
        deferred = defer.Deferred()

        self._get_events(
            deferred, user, pagination_config.from_token,
            pagination_config.limit, timeout
        ).addErrback(deferred.errback)

        return deferred

    @defer.inlineCallbacks
    def _get_events(self, deferred, user, from_token, limit, timeout):
        if not from_token:
            from_token = yield self.event_sources.get_current_token()

        listener = _NotificationListener(
            user,
            from_token,
            limit,
            timeout,
            deferred,
        )

        if timeout:
            reactor.callLater(timeout/1000, self._timeout_listener, listener)

        yield self._register_with_keys(listener)
        yield self._check_for_updates(listener)

        return

    def _timeout_listener(self, listener):
        # TODO (erikj): We should probably set to_token to the current max
        # rather than reusing from_token.
        listener.notify(
            self,
            [],
            listener.from_token,
            listener.from_token,
        )

    @defer.inlineCallbacks
    @log_function
    def _register_with_keys(self, listener):
        signals_keys = {}

        # TODO (erikj): This can probably be replaced by a DeferredList
        for source in self.event_sources.sources:
            keys = yield source.get_keys_for_user(listener.user)
            signals_keys.setdefault(source.SIGNAL_NAME, []).extend(keys)

        for signal, keys in signals_keys.items():
            for key in keys:
                s = self.signal_keys_to_users.setdefault((signal, key), [])
                s.append(listener)
                listener.signal_key_list.append((signal, key))

        logger.debug("New signal_keys_to_users: %s", self.signal_keys_to_users)

        defer.returnValue(listener)

    @defer.inlineCallbacks
    @log_function
    def _check_for_updates(self, listener):
        # TODO (erikj): We need to think about limits across multiple sources
        events = []

        from_token = listener.from_token
        limit = listener.limit

        # TODO (erikj): DeferredList?
        for source in self.event_sources.sources:
            stuff, new_token = yield source.get_new_events_for_user(
                listener.user,
                from_token,
                limit,
            )

            events.extend(stuff)

            from_token = new_token

        end_token = from_token


        if events:
            listener.notify(self, events, listener.from_token, end_token)

        defer.returnValue(listener)
