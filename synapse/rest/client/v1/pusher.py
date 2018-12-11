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

import logging

from twisted.internet import defer

from synapse.api.errors import Codes, StoreError, SynapseError
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)
from synapse.push import PusherConfigException

from .base import ClientV1RestServlet, client_path_patterns

logger = logging.getLogger(__name__)


class PushersRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/pushers$")

    def __init__(self, hs):
        super(PushersRestServlet, self).__init__(hs)

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user = requester.user

        pushers = yield self.hs.get_datastore().get_pushers_by_user_id(
            user.to_string()
        )

        allowed_keys = [
            "app_display_name",
            "app_id",
            "data",
            "device_display_name",
            "kind",
            "lang",
            "profile_tag",
            "pushkey",
        ]

        for p in pushers:
            for k, v in list(p.items()):
                if k not in allowed_keys:
                    del p[k]

        defer.returnValue((200, {"pushers": pushers}))

    def on_OPTIONS(self, _):
        return 200, {}


class PushersSetRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/pushers/set$")

    def __init__(self, hs):
        super(PushersSetRestServlet, self).__init__(hs)
        self.notifier = hs.get_notifier()
        self.pusher_pool = self.hs.get_pusherpool()

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user = requester.user

        content = parse_json_object_from_request(request)

        if ('pushkey' in content and 'app_id' in content
                and 'kind' in content and
                content['kind'] is None):
            yield self.pusher_pool.remove_pusher(
                content['app_id'], content['pushkey'], user_id=user.to_string()
            )
            defer.returnValue((200, {}))

        assert_params_in_dict(
            content,
            ['kind', 'app_id', 'app_display_name',
             'device_display_name', 'pushkey', 'lang', 'data']
        )

        logger.debug("set pushkey %s to kind %s", content['pushkey'], content['kind'])
        logger.debug("Got pushers request with body: %r", content)

        append = False
        if 'append' in content:
            append = content['append']

        if not append:
            yield self.pusher_pool.remove_pushers_by_app_id_and_pushkey_not_user(
                app_id=content['app_id'],
                pushkey=content['pushkey'],
                not_user_id=user.to_string()
            )

        try:
            yield self.pusher_pool.add_pusher(
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
            raise SynapseError(400, "Config Error: " + str(pce),
                               errcode=Codes.MISSING_PARAM)

        self.notifier.on_new_replication_data()

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


class PushersRemoveRestServlet(RestServlet):
    """
    To allow pusher to be delete by clicking a link (ie. GET request)
    """
    PATTERNS = client_path_patterns("/pushers/remove$")
    SUCCESS_HTML = b"<html><body>You have been unsubscribed</body><html>"

    def __init__(self, hs):
        super(PushersRemoveRestServlet, self).__init__()
        self.hs = hs
        self.notifier = hs.get_notifier()
        self.auth = hs.get_auth()
        self.pusher_pool = self.hs.get_pusherpool()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request, rights="delete_pusher")
        user = requester.user

        app_id = parse_string(request, "app_id", required=True)
        pushkey = parse_string(request, "pushkey", required=True)

        try:
            yield self.pusher_pool.remove_pusher(
                app_id=app_id,
                pushkey=pushkey,
                user_id=user.to_string(),
            )
        except StoreError as se:
            if se.code != 404:
                # This is fine: they're already unsubscribed
                raise

        self.notifier.on_new_replication_data()

        request.setResponseCode(200)
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%d" % (
            len(PushersRemoveRestServlet.SUCCESS_HTML),
        ))
        request.write(PushersRemoveRestServlet.SUCCESS_HTML)
        finish_request(request)
        defer.returnValue(None)

    def on_OPTIONS(self, _):
        return 200, {}


def register_servlets(hs, http_server):
    PushersRestServlet(hs).register(http_server)
    PushersSetRestServlet(hs).register(http_server)
    PushersRemoveRestServlet(hs).register(http_server)
