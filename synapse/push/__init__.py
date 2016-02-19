# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
from synapse.types import StreamToken
from synapse.util.logcontext import LoggingContext
from synapse.util.metrics import Measure

import synapse.util.async
import push_rule_evaluator as push_rule_evaluator

import logging
import random

logger = logging.getLogger(__name__)


_NEXT_ID = 1


def _get_next_id():
    global _NEXT_ID
    _id = _NEXT_ID
    _NEXT_ID += 1
    return _id


# Pushers could now be moved to pull out of the event_push_actions table instead
# of listening on the event stream: this would avoid them having to run the
# rules again.
class Pusher(object):
    INITIAL_BACKOFF = 1000
    MAX_BACKOFF = 60 * 60 * 1000
    GIVE_UP_AFTER = 24 * 60 * 60 * 1000

    def __init__(self, _hs, user_id, app_id,
                 app_display_name, device_display_name, pushkey, pushkey_ts,
                 data, last_token, last_success, failing_since):
        self.hs = _hs
        self.evStreamHandler = self.hs.get_handlers().event_stream_handler
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()
        self.user_id = user_id
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
        self.badge = None

        self.name = "Pusher-%d" % (_get_next_id(),)

        # The last value of last_active_time that we saw
        self.last_last_active_time = 0
        self.has_unread = True

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
        for mev in their_member_events_for_room:
            if mev.content['membership'] == 'join' and 'displayname' in mev.content:
                dn = mev.content['displayname']
                if dn is not None:
                    ctx['sender_display_name'] = dn

        defer.returnValue(ctx)

    @defer.inlineCallbacks
    def start(self):
        with LoggingContext(self.name):
            if not self.last_token:
                # First-time setup: get a token to start from (we can't
                # just start from no token, ie. 'now'
                # because we need the result to be reproduceable in case
                # we fail to dispatch the push)
                config = PaginationConfig(from_token=None, limit='1')
                chunk = yield self.evStreamHandler.get_stream(
                    self.user_id, config, timeout=0, affect_presence=False
                )
                self.last_token = chunk['end']
                yield self.store.update_pusher_last_token(
                    self.app_id, self.pushkey, self.user_id, self.last_token
                )
                logger.info("New pusher %s for user %s starting from token %s",
                            self.pushkey, self.user_id, self.last_token)

            else:
                logger.info(
                    "Old pusher %s for user %s starting",
                    self.pushkey, self.user_id,
                )

            wait = 0
            while self.alive:
                try:
                    if wait > 0:
                        yield synapse.util.async.sleep(wait)
                    with Measure(self.clock, "push"):
                        yield self.get_and_dispatch()
                    wait = 0
                except:
                    if wait == 0:
                        wait = 1
                    else:
                        wait = min(wait * 2, 1800)
                    logger.exception(
                        "Exception in pusher loop for pushkey %s. Pausing for %ds",
                        self.pushkey, wait
                    )

    @defer.inlineCallbacks
    def get_and_dispatch(self):
        from_tok = StreamToken.from_string(self.last_token)
        config = PaginationConfig(from_token=from_tok, limit='1')
        timeout = (300 + random.randint(-60, 60)) * 1000
        chunk = yield self.evStreamHandler.get_stream(
            self.user_id, config, timeout=timeout, affect_presence=False,
            only_keys=("room", "receipt",),
        )

        # limiting to 1 may get 1 event plus 1 presence event, so
        # pick out the actual event
        single_event = None
        read_receipt = None
        for c in chunk['chunk']:
            if 'event_id' in c:  # Hmmm...
                single_event = c
            elif c['type'] == 'm.receipt':
                read_receipt = c

        have_updated_badge = False
        if read_receipt:
            for receipt_part in read_receipt['content'].values():
                if 'm.read' in receipt_part:
                    if self.user_id in receipt_part['m.read'].keys():
                        have_updated_badge = True

        if not single_event:
            if have_updated_badge:
                yield self.update_badge()
            self.last_token = chunk['end']
            yield self.store.update_pusher_last_token(
                self.app_id,
                self.pushkey,
                self.user_id,
                self.last_token
            )
            return

        if not self.alive:
            return

        processed = False

        rule_evaluator = yield \
            push_rule_evaluator.evaluator_for_user_id(
                self.user_id, single_event['room_id'], self.store
            )

        actions = yield rule_evaluator.actions_for_event(single_event)
        tweaks = rule_evaluator.tweaks_for_actions(actions)

        if 'notify' in actions:
            self.badge = yield self._get_badge_count()
            rejected = yield self.dispatch_push(single_event, tweaks, self.badge)
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
                            self.app_id, pk, self.user_id
                        )
        else:
            if have_updated_badge:
                yield self.update_badge()
            processed = True

        if not self.alive:
            return

        if processed:
            self.backoff_delay = Pusher.INITIAL_BACKOFF
            self.last_token = chunk['end']
            yield self.store.update_pusher_last_token_and_success(
                self.app_id,
                self.pushkey,
                self.user_id,
                self.last_token,
                self.clock.time_msec()
            )
            if self.failing_since:
                self.failing_since = None
                yield self.store.update_pusher_failing_since(
                    self.app_id,
                    self.pushkey,
                    self.user_id,
                    self.failing_since)
        else:
            if not self.failing_since:
                self.failing_since = self.clock.time_msec()
                yield self.store.update_pusher_failing_since(
                    self.app_id,
                    self.pushkey,
                    self.user_id,
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
                            self.user_id, self.pushkey)
                self.backoff_delay = Pusher.INITIAL_BACKOFF
                self.last_token = chunk['end']
                yield self.store.update_pusher_last_token(
                    self.app_id,
                    self.pushkey,
                    self.user_id,
                    self.last_token
                )

                self.failing_since = None
                yield self.store.update_pusher_failing_since(
                    self.app_id,
                    self.pushkey,
                    self.user_id,
                    self.failing_since
                )
            else:
                logger.warn("Failed to dispatch push for user %s "
                            "(failing for %dms)."
                            "Trying again in %dms",
                            self.user_id,
                            self.clock.time_msec() - self.failing_since,
                            self.backoff_delay)
                yield synapse.util.async.sleep(self.backoff_delay / 1000.0)
                self.backoff_delay *= 2
                if self.backoff_delay > Pusher.MAX_BACKOFF:
                    self.backoff_delay = Pusher.MAX_BACKOFF

    def stop(self):
        self.alive = False

    def dispatch_push(self, p, tweaks, badge):
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

    @defer.inlineCallbacks
    def update_badge(self):
        new_badge = yield self._get_badge_count()
        if self.badge != new_badge:
            self.badge = new_badge
            yield self.send_badge(self.badge)

    def send_badge(self, badge):
        """
        Overridden by implementing classes to send an updated badge count
        """
        pass

    @defer.inlineCallbacks
    def _get_badge_count(self):
        invites, joins = yield defer.gatherResults([
            self.store.get_invites_for_user(self.user_id),
            self.store.get_rooms_for_user(self.user_id),
        ], consumeErrors=True)

        my_receipts_by_room = yield self.store.get_receipts_for_user(
            self.user_id,
            "m.read",
        )

        badge = len(invites)

        for r in joins:
            if r.room_id in my_receipts_by_room:
                last_unread_event_id = my_receipts_by_room[r.room_id]

                notifs = yield (
                    self.store.get_unread_event_push_actions_by_room_for_user(
                        r.room_id, self.user_id, last_unread_event_id
                    )
                )
                badge += notifs["notify_count"]
        defer.returnValue(badge)


class PusherConfigException(Exception):
    def __init__(self, msg):
        super(PusherConfigException, self).__init__(msg)
