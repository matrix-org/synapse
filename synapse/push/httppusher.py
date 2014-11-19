# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

import logging

logger = logging.getLogger(__name__)

class HttpPusher(Pusher):
    def __init__(self, _hs, user_name, app, app_display_name, device_display_name, pushkey, data, last_token):
        super(HttpPusher, self).__init__(_hs,
                                         user_name,
                                         app,
                                         app_display_name,
                                         device_display_name,
                                         pushkey,
                                         data,
                                         last_token)
        if 'url' not in data:
            raise PusherConfigException("'url' required in data for HTTP pusher")
        self.url = data['url']

    def dispatchPush(self, event):
        print event
        return True

