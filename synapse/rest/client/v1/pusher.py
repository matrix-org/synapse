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

from synapse.api.errors import Codes, StoreError, SynapseError
from synapse.http.server import respond_with_html_bytes
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)
from synapse.push import PusherConfigException
from synapse.rest.client.v2_alpha._base import client_patterns

logger = logging.getLogger(__name__)

ALLOWED_KEYS = {
    "app_display_name",
    "app_id",
    "data",
    "device_display_name",
    "kind",
    "lang",
    "profile_tag",
    "pushkey",
}


class PushersRestServlet(RestServlet):
    PATTERNS = client_patterns("/pushers$", v1=True)

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request)
        user = requester.user

        pushers = await self.hs.get_datastore().get_pushers_by_user_id(user.to_string())

        filtered_pushers = [
            {k: v for k, v in p.items() if k in ALLOWED_KEYS} for p in pushers
        ]

        return 200, {"pushers": filtered_pushers}

    def on_OPTIONS(self, _):
        return 200, {}


class PushersSetRestServlet(RestServlet):
    PATTERNS = client_patterns("/pushers/set$", v1=True)

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.pusher_pool = self.hs.get_pusherpool()

    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request)
        user = requester.user

        content = parse_json_object_from_request(request)

        if (
            "pushkey" in content
            and "app_id" in content
            and "kind" in content
            and content["kind"] is None
        ):
            await self.pusher_pool.remove_pusher(
                content["app_id"], content["pushkey"], user_id=user.to_string()
            )
            return 200, {}

        assert_params_in_dict(
            content,
            [
                "kind",
                "app_id",
                "app_display_name",
                "device_display_name",
                "pushkey",
                "lang",
                "data",
            ],
        )

        logger.debug("set pushkey %s to kind %s", content["pushkey"], content["kind"])
        logger.debug("Got pushers request with body: %r", content)

        append = False
        if "append" in content:
            append = content["append"]

        if not append:
            await self.pusher_pool.remove_pushers_by_app_id_and_pushkey_not_user(
                app_id=content["app_id"],
                pushkey=content["pushkey"],
                not_user_id=user.to_string(),
            )

        try:
            await self.pusher_pool.add_pusher(
                user_id=user.to_string(),
                access_token=requester.access_token_id,
                kind=content["kind"],
                app_id=content["app_id"],
                app_display_name=content["app_display_name"],
                device_display_name=content["device_display_name"],
                pushkey=content["pushkey"],
                lang=content["lang"],
                data=content["data"],
                profile_tag=content.get("profile_tag", ""),
            )
        except PusherConfigException as pce:
            raise SynapseError(
                400, "Config Error: " + str(pce), errcode=Codes.MISSING_PARAM
            )

        self.notifier.on_new_replication_data()

        return 200, {}

    def on_OPTIONS(self, _):
        return 200, {}


class PushersRemoveRestServlet(RestServlet):
    """
    To allow pusher to be delete by clicking a link (ie. GET request)
    """

    PATTERNS = client_patterns("/pushers/remove$", v1=True)
    SUCCESS_HTML = b"<html><body>You have been unsubscribed</body><html>"

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.notifier = hs.get_notifier()
        self.auth = hs.get_auth()
        self.pusher_pool = self.hs.get_pusherpool()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request, rights="delete_pusher")
        user = requester.user

        app_id = parse_string(request, "app_id", required=True)
        pushkey = parse_string(request, "pushkey", required=True)

        try:
            await self.pusher_pool.remove_pusher(
                app_id=app_id, pushkey=pushkey, user_id=user.to_string()
            )
        except StoreError as se:
            if se.code != 404:
                # This is fine: they're already unsubscribed
                raise

        self.notifier.on_new_replication_data()

        respond_with_html_bytes(
            request, 200, PushersRemoveRestServlet.SUCCESS_HTML,
        )
        return None

    def on_OPTIONS(self, _):
        return 200, {}


def register_servlets(hs, http_server):
    PushersRestServlet(hs).register(http_server)
    PushersSetRestServlet(hs).register(http_server)
    PushersRemoveRestServlet(hs).register(http_server)
