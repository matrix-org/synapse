# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.streams.config import PaginationConfig
from synapse.types import StreamToken, UserID

import synapse.util.async
import baserules

import logging
import fnmatch
import json

logger = logging.getLogger(__name__)


class Pusher(object):
    INITIAL_BACKOFF = 1000
    MAX_BACKOFF = 60 * 60 * 1000
    GIVE_UP_AFTER = 24 * 60 * 60 * 1000
    DEFAULT_ACTIONS = ['notify']

    def __init__(self, _hs, instance_handle, user_name, app_id,
                 app_display_name, device_display_name, pushkey, pushkey_ts,
                 data, last_token, last_success, failing_since):
        self.hs = _hs
        self.evStreamHandler = self.hs.get_handlers().event_stream_handler
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()
        self.instance_handle = instance_handle
        self.user_name = user_name
        self.app_id = app_id
        self.app_display_name = app_display_name
        self.device_display_name = device_display_name
        self.pushkey = pushkey
        self.pushkey_ts = pushkey_ts
        self.data = data
        self.last_token = last_token
        self.last_success = last_success  # not actually used
        self.backoff_delay = Pusher.INITIAL_BACKOFF
        self.failing_since = failing_since
        self.alive = True

        # The last value of last_active_time that we saw
        self.last_last_active_time = 0
        self.has_unread = True

    @defer.inlineCallbacks
    def _actions_for_event(self, ev):
        """
        This should take into account notification settings that the user
        has configured both globally and per-room when we have the ability
        to do such things.
        """
        if ev['user_id'] == self.user_name:
            # let's assume you probably know about messages you sent yourself
            defer.returnValue(['dont_notify'])

        if ev['type'] == 'm.room.member':
            if ev['state_key'] != self.user_name:
                defer.returnValue(['dont_notify'])

        rules = yield self.store.get_push_rules_for_user_name(self.user_name)

        for r in rules:
            r['conditions'] = json.loads(r['conditions'])
            r['actions'] = json.loads(r['actions'])

        user_name_localpart = UserID.from_string(self.user_name).localpart

        rules.extend(baserules.make_base_rules(user_name_localpart))

        # get *our* member event for display name matching
        member_events_for_room = yield self.store.get_current_state(
            room_id=ev['room_id'],
            event_type='m.room.member',
            state_key=self.user_name
        )
        my_display_name = None
        if len(member_events_for_room) > 0:
            my_display_name = member_events_for_room[0].content['displayname']

        for r in rules:
            matches = True

            conditions = r['conditions']
            actions = r['actions']

            for c in conditions:
                matches &= self._event_fulfills_condition(
                    ev, c, display_name=my_display_name
                )
            # ignore rules with no actions (we have an explict 'dont_notify'
            if len(actions) == 0:
                logger.warn(
                    "Ignoring rule id %s with no actions for user %s" %
                    (r['rule_id'], r['user_name'])
                )
                continue
            if matches:
                defer.returnValue(actions)

        defer.returnValue(Pusher.DEFAULT_ACTIONS)

    def _event_fulfills_condition(self, ev, condition, display_name):
        if condition['kind'] == 'event_match':
            if 'pattern' not in condition:
                logger.warn("event_match condition with no pattern")
                return False
            pat = condition['pattern']

            val = _value_for_dotted_key(condition['key'], ev)
            if val is None:
                return False
            return fnmatch.fnmatch(val.upper(), pat.upper())
        elif condition['kind'] == 'device':
            if 'instance_handle' not in condition:
                return True
            return condition['instance_handle'] == self.instance_handle
        elif condition['kind'] == 'contains_display_name':
            # This is special because display names can be different
            # between rooms and so you can't really hard code it in a rule.
            # Optimisation: we should cache these names and update them from
            # the event stream.
            if 'content' not in ev or 'body' not in ev['content']:
                return False
            return fnmatch.fnmatch(
                ev['content']['body'].upper(), "*%s*" % (display_name.upper(),)
            )
        else:
            return True

    @defer.inlineCallbacks
    def get_context_for_event(self, ev):
        name_aliases = yield self.store.get_room_name_and_aliases(
            ev['room_id']
        )

        ctx = {'aliases': name_aliases[1]}
        if name_aliases[0] is not None:
            ctx['name'] = name_aliases[0]

        their_member_events_for_room = yield self.store.get_current_state(
            room_id=ev['room_id'],
            event_type='m.room.member',
            state_key=ev['user_id']
        )
        if len(their_member_events_for_room) > 0:
            dn = their_member_events_for_room[0].content['displayname']
            if dn is not None:
                ctx['sender_display_name'] = dn

        defer.returnValue(ctx)

    @defer.inlineCallbacks
    def start(self):
        if not self.last_token:
            # First-time setup: get a token to start from (we can't
            # just start from no token, ie. 'now'
            # because we need the result to be reproduceable in case
            # we fail to dispatch the push)
            config = PaginationConfig(from_token=None, limit='1')
            chunk = yield self.evStreamHandler.get_stream(
                self.user_name, config, timeout=0)
            self.last_token = chunk['end']
            self.store.update_pusher_last_token(
                self.user_name, self.pushkey, self.last_token)
            logger.info("Pusher %s for user %s starting from token %s",
                        self.pushkey, self.user_name, self.last_token)

        while self.alive:
            from_tok = StreamToken.from_string(self.last_token)
            config = PaginationConfig(from_token=from_tok, limit='1')
            chunk = yield self.evStreamHandler.get_stream(
                self.user_name, config,
                timeout=100*365*24*60*60*1000, affect_presence=False
            )

            # limiting to 1 may get 1 event plus 1 presence event, so
            # pick out the actual event
            single_event = None
            for c in chunk['chunk']:
                if 'event_id' in c:  # Hmmm...
                    single_event = c
                    break
            if not single_event:
                self.last_token = chunk['end']
                continue

            if not self.alive:
                continue

            processed = False
            actions = yield self._actions_for_event(single_event)
            tweaks = _tweaks_for_actions(actions)

            if len(actions) == 0:
                logger.warn("Empty actions! Using default action.")
                actions = Pusher.DEFAULT_ACTIONS
            if 'notify' not in actions and 'dont_notify' not in actions:
                logger.warn("Neither notify nor dont_notify in actions: adding default")
                actions.extend(Pusher.DEFAULT_ACTIONS)
            if 'dont_notify' in actions:
                logger.debug(
                    "%s for %s: dont_notify",
                    single_event['event_id'], self.user_name
                )
                processed = True
            else:
                rejected = yield self.dispatch_push(single_event, tweaks)
                self.has_unread = True
                if isinstance(rejected, list) or isinstance(rejected, tuple):
                    processed = True
                    for pk in rejected:
                        if pk != self.pushkey:
                            # for sanity, we only remove the pushkey if it
                            # was the one we actually sent...
                            logger.warn(
                                ("Ignoring rejected pushkey %s because we"
                                 " didn't send it"), pk
                            )
                        else:
                            logger.info(
                                "Pushkey %s was rejected: removing",
                                pk
                            )
                            yield self.hs.get_pusherpool().remove_pusher(
                                self.app_id, pk
                            )

            if not self.alive:
                continue

            if processed:
                self.backoff_delay = Pusher.INITIAL_BACKOFF
                self.last_token = chunk['end']
                self.store.update_pusher_last_token_and_success(
                    self.user_name,
                    self.pushkey,
                    self.last_token,
                    self.clock.time_msec()
                )
                if self.failing_since:
                    self.failing_since = None
                    self.store.update_pusher_failing_since(
                        self.user_name,
                        self.pushkey,
                        self.failing_since)
            else:
                if not self.failing_since:
                    self.failing_since = self.clock.time_msec()
                    self.store.update_pusher_failing_since(
                        self.user_name,
                        self.pushkey,
                        self.failing_since
                    )

                if (self.failing_since and
                   self.failing_since <
                   self.clock.time_msec() - Pusher.GIVE_UP_AFTER):
                    # we really only give up so that if the URL gets
                    # fixed, we don't suddenly deliver a load
                    # of old notifications.
                    logger.warn("Giving up on a notification to user %s, "
                                "pushkey %s",
                                self.user_name, self.pushkey)
                    self.backoff_delay = Pusher.INITIAL_BACKOFF
                    self.last_token = chunk['end']
                    self.store.update_pusher_last_token(
                        self.user_name,
                        self.pushkey,
                        self.last_token
                    )

                    self.failing_since = None
                    self.store.update_pusher_failing_since(
                        self.user_name,
                        self.pushkey,
                        self.failing_since
                    )
                else:
                    logger.warn("Failed to dispatch push for user %s "
                                "(failing for %dms)."
                                "Trying again in %dms",
                                self.user_name,
                                self.clock.time_msec() - self.failing_since,
                                self.backoff_delay)
                    yield synapse.util.async.sleep(self.backoff_delay / 1000.0)
                    self.backoff_delay *= 2
                    if self.backoff_delay > Pusher.MAX_BACKOFF:
                        self.backoff_delay = Pusher.MAX_BACKOFF

    def stop(self):
        self.alive = False

    def dispatch_push(self, p, tweaks):
        """
        Overridden by implementing classes to actually deliver the notification
        Args:
            p: The event to notify for as a single event from the event stream
        Returns: If the notification was delivered, an array containing any
                 pushkeys that were rejected by the push gateway.
                 False if the notification could not be delivered (ie.
                 should be retried).
        """
        pass

    def reset_badge_count(self):
        pass

    def presence_changed(self, state):
        """
        We clear badge counts whenever a user's last_active time is bumped
        This is by no means perfect but I think it's the best we can do
        without read receipts.
        """
        if 'last_active' in state.state:
            last_active = state.state['last_active']
            if last_active > self.last_last_active_time:
                self.last_last_active_time = last_active
                if self.has_unread:
                    logger.info("Resetting badge count for %s", self.user_name)
                    self.reset_badge_count()
                    self.has_unread = False


def _value_for_dotted_key(dotted_key, event):
    parts = dotted_key.split(".")
    val = event
    while len(parts) > 0:
        if parts[0] not in val:
            return None
        val = val[parts[0]]
        parts = parts[1:]
    return val


def _tweaks_for_actions(actions):
    tweaks = {}
    for a in actions:
        if not isinstance(a, dict):
            continue
        if 'set_sound' in a:
            tweaks['sound'] = a['set_sound']
    return tweaks


class PusherConfigException(Exception):
    def __init__(self, msg):
        super(PusherConfigException, self).__init__(msg)
