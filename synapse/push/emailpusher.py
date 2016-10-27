# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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
from twisted.internet.error import AlreadyCalled, AlreadyCancelled

import logging

from synapse.util.metrics import Measure
from synapse.util.logcontext import LoggingContext

from mailer import Mailer

logger = logging.getLogger(__name__)

# The amount of time we always wait before ever emailing about a notification
# (to give the user a chance to respond to other push or notice the window)
DELAY_BEFORE_MAIL_MS = 10 * 60 * 1000

# THROTTLE is the minimum time between mail notifications sent for a given room.
# Each room maintains its own throttle counter, but each new mail notification
# sends the pending notifications for all rooms.
THROTTLE_START_MS = 10 * 60 * 1000
THROTTLE_MAX_MS = 24 * 60 * 60 * 1000  # 24h
# THROTTLE_MULTIPLIER = 6              # 10 mins, 1 hour, 6 hours, 24 hours
THROTTLE_MULTIPLIER = 144              # 10 mins, 24 hours - i.e. jump straight to 1 day

# If no event triggers a notification for this long after the previous,
# the throttle is released.
# 12 hours - a gap of 12 hours in conversation is surely enough to merit a new
# notification when things get going again...
THROTTLE_RESET_AFTER_MS = (12 * 60 * 60 * 1000)

# does each email include all unread notifs, or just the ones which have happened
# since the last mail?
# XXX: this is currently broken as it includes ones from parted rooms(!)
INCLUDE_ALL_UNREAD_NOTIFS = False


class EmailPusher(object):
    """
    A pusher that sends email notifications about events (approximately)
    when they happen.
    This shares quite a bit of code with httpusher: it would be good to
    factor out the common parts
    """
    def __init__(self, hs, pusherdict):
        self.hs = hs
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()
        self.pusher_id = pusherdict['id']
        self.user_id = pusherdict['user_name']
        self.app_id = pusherdict['app_id']
        self.email = pusherdict['pushkey']
        self.last_stream_ordering = pusherdict['last_stream_ordering']
        self.timed_call = None
        self.throttle_params = None

        # See httppusher
        self.max_stream_ordering = None

        self.processing = False

        if self.hs.config.email_enable_notifs:
            if 'data' in pusherdict and 'brand' in pusherdict['data']:
                app_name = pusherdict['data']['brand']
            else:
                app_name = self.hs.config.email_app_name

            self.mailer = Mailer(self.hs, app_name)
        else:
            self.mailer = None

    @defer.inlineCallbacks
    def on_started(self):
        if self.mailer is not None:
            self.throttle_params = yield self.store.get_throttle_params_by_room(
                self.pusher_id
            )
            yield self._process()

    def on_stop(self):
        if self.timed_call:
            try:
                self.timed_call.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass
            self.timed_call = None

    @defer.inlineCallbacks
    def on_new_notifications(self, min_stream_ordering, max_stream_ordering):
        self.max_stream_ordering = max(max_stream_ordering, self.max_stream_ordering)
        yield self._process()

    def on_new_receipts(self, min_stream_id, max_stream_id):
        # We could wake up and cancel the timer but there tend to be quite a
        # lot of read receipts so it's probably less work to just let the
        # timer fire
        return defer.succeed(None)

    @defer.inlineCallbacks
    def on_timer(self):
        self.timed_call = None
        yield self._process()

    @defer.inlineCallbacks
    def _process(self):
        if self.processing:
            return

        with LoggingContext("emailpush._process"):
            with Measure(self.clock, "emailpush._process"):
                try:
                    self.processing = True
                    # if the max ordering changes while we're running _unsafe_process,
                    # call it again, and so on until we've caught up.
                    while True:
                        starting_max_ordering = self.max_stream_ordering
                        try:
                            yield self._unsafe_process()
                        except:
                            logger.exception("Exception processing notifs")
                        if self.max_stream_ordering == starting_max_ordering:
                            break
                finally:
                    self.processing = False

    @defer.inlineCallbacks
    def _unsafe_process(self):
        """
        Main logic of the push loop without the wrapper function that sets
        up logging, measures and guards against multiple instances of it
        being run.
        """
        start = 0 if INCLUDE_ALL_UNREAD_NOTIFS else self.last_stream_ordering
        fn = self.store.get_unread_push_actions_for_user_in_range_for_email
        unprocessed = yield fn(self.user_id, start, self.max_stream_ordering)

        soonest_due_at = None

        if not unprocessed:
            yield self.save_last_stream_ordering_and_success(self.max_stream_ordering)
            return

        for push_action in unprocessed:
            received_at = push_action['received_ts']
            if received_at is None:
                received_at = 0
            notif_ready_at = received_at + DELAY_BEFORE_MAIL_MS

            room_ready_at = self.room_ready_to_notify_at(
                push_action['room_id']
            )

            should_notify_at = max(notif_ready_at, room_ready_at)

            if should_notify_at < self.clock.time_msec():
                # one of our notifications is ready for sending, so we send
                # *one* email updating the user on their notifications,
                # we then consider all previously outstanding notifications
                # to be delivered.

                reason = {
                    'room_id': push_action['room_id'],
                    'now': self.clock.time_msec(),
                    'received_at': received_at,
                    'delay_before_mail_ms': DELAY_BEFORE_MAIL_MS,
                    'last_sent_ts': self.get_room_last_sent_ts(push_action['room_id']),
                    'throttle_ms': self.get_room_throttle_ms(push_action['room_id']),
                }

                yield self.send_notification(unprocessed, reason)

                yield self.save_last_stream_ordering_and_success(max([
                    ea['stream_ordering'] for ea in unprocessed
                ]))

                # we update the throttle on all the possible unprocessed push actions
                for ea in unprocessed:
                    yield self.sent_notif_update_throttle(
                        ea['room_id'], ea
                    )
                break
            else:
                if soonest_due_at is None or should_notify_at < soonest_due_at:
                    soonest_due_at = should_notify_at

                if self.timed_call is not None:
                    try:
                        self.timed_call.cancel()
                    except (AlreadyCalled, AlreadyCancelled):
                        pass
                    self.timed_call = None

        if soonest_due_at is not None:
            self.timed_call = reactor.callLater(
                self.seconds_until(soonest_due_at), self.on_timer
            )

    @defer.inlineCallbacks
    def save_last_stream_ordering_and_success(self, last_stream_ordering):
        self.last_stream_ordering = last_stream_ordering
        yield self.store.update_pusher_last_stream_ordering_and_success(
            self.app_id, self.email, self.user_id,
            last_stream_ordering, self.clock.time_msec()
        )

    def seconds_until(self, ts_msec):
        return (ts_msec - self.clock.time_msec()) / 1000

    def get_room_throttle_ms(self, room_id):
        if room_id in self.throttle_params:
            return self.throttle_params[room_id]["throttle_ms"]
        else:
            return 0

    def get_room_last_sent_ts(self, room_id):
        if room_id in self.throttle_params:
            return self.throttle_params[room_id]["last_sent_ts"]
        else:
            return 0

    def room_ready_to_notify_at(self, room_id):
        """
        Determines whether throttling should prevent us from sending an email
        for the given room
        Returns: The timestamp when we are next allowed to send an email notif
        for this room
        """
        last_sent_ts = self.get_room_last_sent_ts(room_id)
        throttle_ms = self.get_room_throttle_ms(room_id)

        may_send_at = last_sent_ts + throttle_ms
        return may_send_at

    @defer.inlineCallbacks
    def sent_notif_update_throttle(self, room_id, notified_push_action):
        # We have sent a notification, so update the throttle accordingly.
        # If the event that triggered the notif happened more than
        # THROTTLE_RESET_AFTER_MS after the previous one that triggered a
        # notif, we release the throttle. Otherwise, the throttle is increased.
        time_of_previous_notifs = yield self.store.get_time_of_last_push_action_before(
            notified_push_action['stream_ordering']
        )

        time_of_this_notifs = notified_push_action['received_ts']

        if time_of_previous_notifs is not None and time_of_this_notifs is not None:
            gap = time_of_this_notifs - time_of_previous_notifs
        else:
            # if we don't know the arrival time of one of the notifs (it was not
            # stored prior to email notification code) then assume a gap of
            # zero which will just not reset the throttle
            gap = 0

        current_throttle_ms = self.get_room_throttle_ms(room_id)

        if gap > THROTTLE_RESET_AFTER_MS:
            new_throttle_ms = THROTTLE_START_MS
        else:
            if current_throttle_ms == 0:
                new_throttle_ms = THROTTLE_START_MS
            else:
                new_throttle_ms = min(
                    current_throttle_ms * THROTTLE_MULTIPLIER,
                    THROTTLE_MAX_MS
                )
        self.throttle_params[room_id] = {
            "last_sent_ts": self.clock.time_msec(),
            "throttle_ms": new_throttle_ms
        }
        yield self.store.set_throttle_params(
            self.pusher_id, room_id, self.throttle_params[room_id]
        )

    @defer.inlineCallbacks
    def send_notification(self, push_actions, reason):
        logger.info("Sending notif email for user %r", self.user_id)

        yield self.mailer.send_notification_mail(
            self.app_id, self.user_id, self.email, push_actions, reason
        )
