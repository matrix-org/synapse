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

from synapse.push import Pusher, PusherConfigException
from synapse.http.client import SimpleHttpClient

from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class HttpPusher(Pusher):
    def __init__(self, _hs, profile_tag, user_name, app_id,
                 app_display_name, device_display_name, pushkey, pushkey_ts,
                 data, last_token, last_success, failing_since):
        super(HttpPusher, self).__init__(
            _hs,
            profile_tag,
            user_name,
            app_id,
            app_display_name,
            device_display_name,
            pushkey,
            pushkey_ts,
            data,
            last_token,
            last_success,
            failing_since
        )
        if 'url' not in data:
            raise PusherConfigException(
                "'url' required in data for HTTP pusher"
            )
        self.url = data['url']
        self.httpCli = SimpleHttpClient(self.hs)
        self.data_minus_url = {}
        self.data_minus_url.update(self.data)
        del self.data_minus_url['url']

    @defer.inlineCallbacks
    def _build_notification_dict(self, event, tweaks):
        # we probably do not want to push for every presence update
        # (we may want to be able to set up notifications when specific
        # people sign in, but we'd want to only deliver the pertinent ones)
        # Actually, presence events will not get this far now because we
        # need to filter them out in the main Pusher code.
        if 'event_id' not in event:
            defer.returnValue(None)

        ctx = yield self.get_context_for_event(event)

        d = {
            'notification': {
                'id': event['event_id'],
                'room_id': event['room_id'],
                'type': event['type'],
                'sender': event['user_id'],
                'counts': {  # -- we don't mark messages as read yet so
                             # we have no way of knowing
                    # Just set the badge to 1 until we have read receipts
                    'unread': 1,
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
        if event['type'] == 'm.room.member':
            d['notification']['membership'] = event['content']['membership']
        if 'content' in event:
            d['notification']['content'] = event['content']

        if len(ctx['aliases']):
            d['notification']['room_alias'] = ctx['aliases'][0]
        if 'sender_display_name' in ctx and len(ctx['sender_display_name']) > 0:
            d['notification']['sender_display_name'] = ctx['sender_display_name']
        if 'name' in ctx and len(ctx['name']) > 0:
            d['notification']['room_name'] = ctx['name']

        defer.returnValue(d)

    @defer.inlineCallbacks
    def dispatch_push(self, event, tweaks):
        notification_dict = yield self._build_notification_dict(event, tweaks)
        if not notification_dict:
            defer.returnValue([])
        try:
            resp = yield self.httpCli.post_json_get_json(self.url, notification_dict)
        except:
            logger.exception("Failed to push %s ", self.url)
            defer.returnValue(False)
        rejected = []
        if 'rejected' in resp:
            rejected = resp['rejected']
        defer.returnValue(rejected)

    @defer.inlineCallbacks
    def reset_badge_count(self):
        d = {
            'notification': {
                'id': '',
                'type': None,
                'sender': '',
                'counts': {
                    'unread': 0,
                    'missed_calls': 0
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
            resp = yield self.httpCli.post_json_get_json(self.url, d)
        except:
            logger.exception("Failed to push %s ", self.url)
            defer.returnValue(False)
        rejected = []
        if 'rejected' in resp:
            rejected = resp['rejected']
        defer.returnValue(rejected)
