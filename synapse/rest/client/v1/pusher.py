# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from synapse.api.errors import SynapseError, Codes
from synapse.push import PusherConfigException
from synapse.http.servlet import parse_json_object_from_request

from .base import ClientV1RestServlet, client_path_patterns

import logging

logger = logging.getLogger(__name__)


class PusherRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/pushers/set$")

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user = requester.user

        content = parse_json_object_from_request(request)

        pusher_pool = self.hs.get_pusherpool()

        if ('pushkey' in content and 'app_id' in content
                and 'kind' in content and
                content['kind'] is None):
            yield pusher_pool.remove_pusher(
                content['app_id'], content['pushkey'], user_id=user.to_string()
            )
            defer.returnValue((200, {}))

        reqd = ['kind', 'app_id', 'app_display_name',
                'device_display_name', 'pushkey', 'lang', 'data']
        missing = []
        for i in reqd:
            if i not in content:
                missing.append(i)
        if len(missing):
            raise SynapseError(400, "Missing parameters: " + ','.join(missing),
                               errcode=Codes.MISSING_PARAM)

        logger.debug("set pushkey %s to kind %s", content['pushkey'], content['kind'])
        logger.debug("Got pushers request with body: %r", content)

        append = False
        if 'append' in content:
            append = content['append']

        if not append:
            yield pusher_pool.remove_pushers_by_app_id_and_pushkey_not_user(
                app_id=content['app_id'],
                pushkey=content['pushkey'],
                not_user_id=user.to_string()
            )

        try:
            yield pusher_pool.add_pusher(
                user_id=user.to_string(),
                access_token=requester.access_token_id,
                kind=content['kind'],
                app_id=content['app_id'],
                app_display_name=content['app_display_name'],
                device_display_name=content['device_display_name'],
                pushkey=content['pushkey'],
                lang=content['lang'],
                data=content['data'],
                profile_tag=content.get('profile_tag', ""),
            )
        except PusherConfigException as pce:
            raise SynapseError(400, "Config Error: " + pce.message,
                               errcode=Codes.MISSING_PARAM)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


def register_servlets(hs, http_server):
    PusherRestServlet(hs).register(http_server)
