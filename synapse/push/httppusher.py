# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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

import six

from prometheus_client import Counter

from twisted.internet import defer
from twisted.internet.error import AlreadyCalled, AlreadyCancelled

from synapse.push import PusherConfigException
from synapse.util.logcontext import LoggingContext
from synapse.util.metrics import Measure

from . import push_rule_evaluator, push_tools

if six.PY3:
    long = int

logger = logging.getLogger(__name__)

http_push_processed_counter = Counter("synapse_http_httppusher_http_pushes_processed", "")

http_push_failed_counter = Counter("synapse_http_httppusher_http_pushes_failed", "")


class HttpPusher(object):
    INITIAL_BACKOFF_SEC = 1  # in seconds because that's what Twisted takes
    MAX_BACKOFF_SEC = 60 * 60

    # This one's in ms because we compare it against the clock
    GIVE_UP_AFTER_MS = 24 * 60 * 60 * 1000

    def __init__(self, hs, pusherdict):
        self.hs = hs
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()
        self.state_handler = self.hs.get_state_handler()
        self.user_id = pusherdict['user_name']
        self.app_id = pusherdict['app_id']
        self.app_display_name = pusherdict['app_display_name']
        self.device_display_name = pusherdict['device_display_name']
        self.pushkey = pusherdict['pushkey']
        self.pushkey_ts = pusherdict['ts']
        self.data = pusherdict['data']
        self.last_stream_ordering = pusherdict['last_stream_ordering']
        self.backoff_delay = HttpPusher.INITIAL_BACKOFF_SEC
        self.failing_since = pusherdict['failing_since']
        self.timed_call = None
        self.processing = False

        # This is the highest stream ordering we know it's safe to process.
        # When new events arrive, we'll be given a window of new events: we
        # should honour this rather than just looking for anything higher
        # because of potential out-of-order event serialisation. This starts
        # off as None though as we don't know any better.
        self.max_stream_ordering = None

        if 'data' not in pusherdict:
            raise PusherConfigException(
                "No 'data' key for HTTP pusher"
            )
        self.data = pusherdict['data']

        self.name = "%s/%s/%s" % (
            pusherdict['user_name'],
            pusherdict['app_id'],
            pusherdict['pushkey'],
        )

        if 'url' not in self.data:
            raise PusherConfigException(
                "'url' required in data for HTTP pusher"
            )
        self.url = self.data['url']
        self.http_client = hs.get_simple_http_client()
        self.data_minus_url = {}
        self.data_minus_url.update(self.data)
        del self.data_minus_url['url']

    @defer.inlineCallbacks
    def on_started(self):
        try:
            yield self._process()
        except Exception:
            logger.exception("Error starting http pusher")

    @defer.inlineCallbacks
    def on_new_notifications(self, min_stream_ordering, max_stream_ordering):
        self.max_stream_ordering = max(max_stream_ordering, self.max_stream_ordering or 0)
        yield self._process()

    @defer.inlineCallbacks
    def on_new_receipts(self, min_stream_id, max_stream_id):
        # Note that the min here shouldn't be relied upon to be accurate.

        # We could check the receipts are actually m.read receipts here,
        # but currently that's the only type of receipt anyway...
        with LoggingContext("push.on_new_receipts"):
            with Measure(self.clock, "push.on_new_receipts"):
                badge = yield push_tools.get_badge_count(
                    self.hs.get_datastore(), self.user_id
                )
            yield self._send_badge(badge)

    @defer.inlineCallbacks
    def on_timer(self):
        yield self._process()

    def on_stop(self):
        if self.timed_call:
            try:
                self.timed_call.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass
            self.timed_call = None

    @defer.inlineCallbacks
    def _process(self):
        if self.processing:
            return

        with LoggingContext("push._process"):
            with Measure(self.clock, "push._process"):
                try:
                    self.processing = True
                    # if the max ordering changes while we're running _unsafe_process,
                    # call it again, and so on until we've caught up.
                    while True:
                        starting_max_ordering = self.max_stream_ordering
                        try:
                            yield self._unsafe_process()
                        except Exception:
                            logger.exception("Exception processing notifs")
                        if self.max_stream_ordering == starting_max_ordering:
                            break
                finally:
                    self.processing = False

    @defer.inlineCallbacks
    def _unsafe_process(self):
        """
        Looks for unset notifications and dispatch them, in order
        Never call this directly: use _process which will only allow this to
        run once per pusher.
        """

        fn = self.store.get_unread_push_actions_for_user_in_range_for_http
        unprocessed = yield fn(
            self.user_id, self.last_stream_ordering, self.max_stream_ordering
        )

        logger.info(
            "Processing %i unprocessed push actions for %s starting at "
            "stream_ordering %s",
            len(unprocessed), self.name, self.last_stream_ordering,
        )

        for push_action in unprocessed:
            processed = yield self._process_one(push_action)
            if processed:
                http_push_processed_counter.inc()
                self.backoff_delay = HttpPusher.INITIAL_BACKOFF_SEC
                self.last_stream_ordering = push_action['stream_ordering']
                yield self.store.update_pusher_last_stream_ordering_and_success(
                    self.app_id, self.pushkey, self.user_id,
                    self.last_stream_ordering,
                    self.clock.time_msec()
                )
                if self.failing_since:
                    self.failing_since = None
                    yield self.store.update_pusher_failing_since(
                        self.app_id, self.pushkey, self.user_id,
                        self.failing_since
                    )
            else:
                http_push_failed_counter.inc()
                if not self.failing_since:
                    self.failing_since = self.clock.time_msec()
                    yield self.store.update_pusher_failing_since(
                        self.app_id, self.pushkey, self.user_id,
                        self.failing_since
                    )

                if (
                    self.failing_since and
                    self.failing_since <
                    self.clock.time_msec() - HttpPusher.GIVE_UP_AFTER_MS
                ):
                    # we really only give up so that if the URL gets
                    # fixed, we don't suddenly deliver a load
                    # of old notifications.
                    logger.warn("Giving up on a notification to user %s, "
                                "pushkey %s",
                                self.user_id, self.pushkey)
                    self.backoff_delay = HttpPusher.INITIAL_BACKOFF_SEC
                    self.last_stream_ordering = push_action['stream_ordering']
                    yield self.store.update_pusher_last_stream_ordering(
                        self.app_id,
                        self.pushkey,
                        self.user_id,
                        self.last_stream_ordering
                    )

                    self.failing_since = None
                    yield self.store.update_pusher_failing_since(
                        self.app_id,
                        self.pushkey,
                        self.user_id,
                        self.failing_since
                    )
                else:
                    logger.info("Push failed: delaying for %ds", self.backoff_delay)
                    self.timed_call = self.hs.get_reactor().callLater(
                        self.backoff_delay, self.on_timer
                    )
                    self.backoff_delay = min(self.backoff_delay * 2, self.MAX_BACKOFF_SEC)
                    break

    @defer.inlineCallbacks
    def _process_one(self, push_action):
        if 'notify' not in push_action['actions']:
            defer.returnValue(True)

        tweaks = push_rule_evaluator.tweaks_for_actions(push_action['actions'])
        badge = yield push_tools.get_badge_count(self.hs.get_datastore(), self.user_id)

        event = yield self.store.get_event(push_action['event_id'], allow_none=True)
        if event is None:
            defer.returnValue(True)  # It's been redacted
        rejected = yield self.dispatch_push(event, tweaks, badge)
        if rejected is False:
            defer.returnValue(False)

        if isinstance(rejected, list) or isinstance(rejected, tuple):
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
                    yield self.hs.remove_pusher(
                        self.app_id, pk, self.user_id
                    )
        defer.returnValue(True)

    @defer.inlineCallbacks
    def _build_notification_dict(self, event, tweaks, badge):
        if self.data.get('format') == 'event_id_only':
            d = {
                'notification': {
                    'event_id': event.event_id,
                    'room_id': event.room_id,
                    'counts': {
                        'unread': badge,
                    },
                    'devices': [
                        {
                            'app_id': self.app_id,
                            'pushkey': self.pushkey,
                            'pushkey_ts': long(self.pushkey_ts / 1000),
                            'data': self.data_minus_url,
                        }
                    ]
                }
            }
            defer.returnValue(d)

        ctx = yield push_tools.get_context_for_event(
            self.store, self.state_handler, event, self.user_id
        )

        d = {
            'notification': {
                'id': event.event_id,  # deprecated: remove soon
                'event_id': event.event_id,
                'room_id': event.room_id,
                'type': event.type,
                'sender': event.user_id,
                'counts': {  # -- we don't mark messages as read yet so
                             # we have no way of knowing
                    # Just set the badge to 1 until we have read receipts
                    'unread': badge,
                    # 'missed_calls': 2
                },
                'devices': [
                    {
                        'app_id': self.app_id,
                        'pushkey': self.pushkey,
                        'pushkey_ts': long(self.pushkey_ts / 1000),
                        'data': self.data_minus_url,
                        'tweaks': tweaks
                    }
                ]
            }
        }
        if event.type == 'm.room.member':
            d['notification']['membership'] = event.content['membership']
            d['notification']['user_is_target'] = event.state_key == self.user_id
        if self.hs.config.push_include_content and 'content' in event:
            d['notification']['content'] = event.content

        # We no longer send aliases separately, instead, we send the human
        # readable name of the room, which may be an alias.
        if 'sender_display_name' in ctx and len(ctx['sender_display_name']) > 0:
            d['notification']['sender_display_name'] = ctx['sender_display_name']
        if 'name' in ctx and len(ctx['name']) > 0:
            d['notification']['room_name'] = ctx['name']

        defer.returnValue(d)

    @defer.inlineCallbacks
    def dispatch_push(self, event, tweaks, badge):
        notification_dict = yield self._build_notification_dict(event, tweaks, badge)
        if not notification_dict:
            defer.returnValue([])
        try:
            resp = yield self.http_client.post_json_get_json(self.url, notification_dict)
        except Exception:
            logger.warn(
                "Failed to push event %s to %s",
                event.event_id, self.name, exc_info=True,
            )
            defer.returnValue(False)
        rejected = []
        if 'rejected' in resp:
            rejected = resp['rejected']
        defer.returnValue(rejected)

    @defer.inlineCallbacks
    def _send_badge(self, badge):
        logger.info("Sending updated badge count %d to %s", badge, self.name)
        d = {
            'notification': {
                'id': '',
                'type': None,
                'sender': '',
                'counts': {
                    'unread': badge
                },
                'devices': [
                    {
                        'app_id': self.app_id,
                        'pushkey': self.pushkey,
                        'pushkey_ts': long(self.pushkey_ts / 1000),
                        'data': self.data_minus_url,
                    }
                ]
            }
        }
        try:
            resp = yield self.http_client.post_json_get_json(self.url, d)
        except Exception:
            logger.warn(
                "Failed to send badge count to %s",
                self.name, exc_info=True,
            )
            defer.returnValue(False)
        rejected = []
        if 'rejected' in resp:
            rejected = resp['rejected']
        defer.returnValue(rejected)
