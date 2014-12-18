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

from twisted.internet import defer

from synapse.api.errors import SynapseError, Codes
from synapse.push import PusherConfigException
from base import RestServlet, client_path_pattern

import json


class PusherRestServlet(RestServlet):
    PATTERN = client_path_pattern("/pushers/set$")

    @defer.inlineCallbacks
    def on_POST(self, request):
        user = yield self.auth.get_user_by_req(request)

        content = _parse_json(request)

        reqd = ['kind', 'app_id', 'app_display_name',
                'device_display_name', 'pushkey', 'data']
        missing = []
        for i in reqd:
            if i not in content:
                missing.append(i)
        if len(missing):
            raise SynapseError(400, "Missing parameters: "+','.join(missing),
                               errcode=Codes.MISSING_PARAM)

        pusher_pool = self.hs.get_pusherpool()
        try:
            yield pusher_pool.add_pusher(
                user_name=user.to_string(),
                kind=content['kind'],
                app_id=content['app_id'],
                app_display_name=content['app_display_name'],
                device_display_name=content['device_display_name'],
                pushkey=content['pushkey'],
                data=content['data']
            )
        except PusherConfigException as pce:
            raise SynapseError(400, "Config Error: "+pce.message,
                               errcode=Codes.MISSING_PARAM)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


# XXX: C+ped from rest/room.py - surely this should be common?
def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.",
                               errcode=Codes.NOT_JSON)
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.", errcode=Codes.NOT_JSON)


def register_servlets(hs, http_server):
    PusherRestServlet(hs).register(http_server)
