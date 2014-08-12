# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
""" This module contains REST servlets to do with presence: /presence/<paths>
"""
from twisted.internet import defer

from base import RestServlet, client_path_pattern

import json
import logging


logger = logging.getLogger(__name__)


class PresenceStatusRestServlet(RestServlet):
    PATTERN = client_path_pattern("/presence/(?P<user_id>[^/]*)/status")

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        auth_user = yield self.auth.get_user_by_req(request)
        user = self.hs.parse_userid(user_id)

        state = yield self.handlers.presence_handler.get_state(
            target_user=user, auth_user=auth_user)

        defer.returnValue((200, state))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        auth_user = yield self.auth.get_user_by_req(request)
        user = self.hs.parse_userid(user_id)

        state = {}
        try:
            content = json.loads(request.content.read())

            state["state"] = content.pop("state")

            if "status_msg" in content:
                state["status_msg"] = content.pop("status_msg")

            if content:
                raise KeyError()
        except:
            defer.returnValue((400, "Unable to parse state"))

        yield self.handlers.presence_handler.set_state(
            target_user=user, auth_user=auth_user, state=state)

        defer.returnValue((200, ""))

    def on_OPTIONS(self, request):
        return (200, {})


class PresenceListRestServlet(RestServlet):
    PATTERN = client_path_pattern("/presence_list/(?P<user_id>[^/]*)")

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        auth_user = yield self.auth.get_user_by_req(request)
        user = self.hs.parse_userid(user_id)

        if not user.is_mine:
            defer.returnValue((400, "User not hosted on this Home Server"))

        if auth_user != user:
            defer.returnValue((400, "Cannot get another user's presence list"))

        presence = yield self.handlers.presence_handler.get_presence_list(
            observer_user=user, accepted=True)

        for p in presence:
            observed_user = p.pop("observed_user")
            p["user_id"] = observed_user.to_string()

        defer.returnValue((200, presence))

    @defer.inlineCallbacks
    def on_POST(self, request, user_id):
        auth_user = yield self.auth.get_user_by_req(request)
        user = self.hs.parse_userid(user_id)

        if not user.is_mine:
            defer.returnValue((400, "User not hosted on this Home Server"))

        if auth_user != user:
            defer.returnValue((
                400, "Cannot modify another user's presence list"))

        try:
            content = json.loads(request.content.read())
        except:
            logger.exception("JSON parse error")
            defer.returnValue((400, "Unable to parse content"))

        deferreds = []

        if "invite" in content:
            for u in content["invite"]:
                invited_user = self.hs.parse_userid(u)
                deferreds.append(self.handlers.presence_handler.send_invite(
                    observer_user=user, observed_user=invited_user))

        if "drop" in content:
            for u in content["drop"]:
                dropped_user = self.hs.parse_userid(u)
                deferreds.append(self.handlers.presence_handler.drop(
                    observer_user=user, observed_user=dropped_user))

        yield defer.DeferredList(deferreds)

        defer.returnValue((200, ""))

    def on_OPTIONS(self, request):
        return (200, {})


def register_servlets(hs, http_server):
    PresenceStatusRestServlet(hs).register(http_server)
    PresenceListRestServlet(hs).register(http_server)
