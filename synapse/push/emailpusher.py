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

import logging

from synapse.util.metrics import Measure
from synapse.util.logcontext import LoggingContext

from mailer import Mailer

logger = logging.getLogger(__name__)

# The amount of time we always wait before ever emailing about a notification
# (to give the user a chance to respond to other push or notice the window)
DELAY_BEFORE_MAIL_MS = 2 * 60 * 1000

THROTTLE_START_MS = 2 * 60 * 1000
THROTTLE_MAX_MS = (2 * 60 * 1000) * (2 ** 11)  # ~3 days

# If no event triggers a notification for this long after the previous,
# the throttle is released.
THROTTLE_RESET_AFTER_MS = (2 * 60 * 1000) * (2 ** 11)  # ~3 days


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
            self.mailer = Mailer(self.hs)
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
            self.timed_call.cancel()

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
        last_notifs = yield self.store.get_time_of_latest_push_action_by_room_for_user(
            self.user_id
        )

        unprocessed = yield self.store.get_unread_push_actions_for_user_in_range(
            self.user_id, self.last_stream_ordering, self.max_stream_ordering
        )

        soonest_due_at = None

        for push_action in unprocessed:
            received_at = push_action['received_ts']
            if received_at is None:
                received_at = 0
            notif_ready_at = received_at + DELAY_BEFORE_MAIL_MS

            room_ready_at = self.room_ready_to_notify_at(
                push_action['room_id'], self.get_room_last_notif_ts(
                    last_notifs, push_action['room_id']
                )
            )

            should_notify_at = max(notif_ready_at, room_ready_at)

            if should_notify_at < self.clock.time_msec():
                # one of our notifications is ready for sending, so we send
                # *one* email updating the user on their notifications,
                # we then consider all previously outstanding notifications
                # to be delivered.
                yield self.send_notification(unprocessed)

                yield self.save_last_stream_ordering_and_success(max([
                    ea['stream_ordering'] for ea in unprocessed
                ]))
                yield self.sent_notif_update_throttle(
                    push_action['room_id'], push_action
                )
            else:
                if soonest_due_at is None or should_notify_at < soonest_due_at:
                    soonest_due_at = should_notify_at

                if self.timed_call is not None:
                    self.timed_call.cancel()
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

    def get_room_last_notif_ts(self, last_notif_by_room, room_id):
        if room_id in last_notif_by_room:
            return last_notif_by_room[room_id]
        else:
            return 0

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

    def room_ready_to_notify_at(self, room_id, last_notif_time):
        """
        Determines whether throttling should prevent us from sending an email
        for the given room
        Returns: True if we should send, False if we should not
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
                    current_throttle_ms * 2,
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
    def send_notification(self, push_actions):
        logger.info("Sending notif email for user %r", self.user_id)
        yield self.mailer.send_notification_mail(
            self.user_id, self.email, push_actions
        )
