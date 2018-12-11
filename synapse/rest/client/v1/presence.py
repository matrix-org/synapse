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

""" This module contains REST servlets to do with presence: /presence/<paths>
"""
import logging

from six import string_types

from twisted.internet import defer

from synapse.api.errors import AuthError, SynapseError
from synapse.handlers.presence import format_user_presence_state
from synapse.http.servlet import parse_json_object_from_request
from synapse.types import UserID

from .base import ClientV1RestServlet, client_path_patterns

logger = logging.getLogger(__name__)


class PresenceStatusRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/presence/(?P<user_id>[^/]*)/status")

    def __init__(self, hs):
        super(PresenceStatusRestServlet, self).__init__(hs)
        self.presence_handler = hs.get_presence_handler()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        if requester.user != user:
            allowed = yield self.presence_handler.is_visible(
                observed_user=user, observer_user=requester.user,
            )

            if not allowed:
                raise AuthError(403, "You are not allowed to see their presence.")

        state = yield self.presence_handler.get_state(target_user=user)
        state = format_user_presence_state(state, self.clock.time_msec())

        defer.returnValue((200, state))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        if requester.user != user:
            raise AuthError(403, "Can only set your own presence state")

        state = {}

        content = parse_json_object_from_request(request)

        try:
            state["presence"] = content.pop("presence")

            if "status_msg" in content:
                state["status_msg"] = content.pop("status_msg")
                if not isinstance(state["status_msg"], string_types):
                    raise SynapseError(400, "status_msg must be a string.")

            if content:
                raise KeyError()
        except SynapseError as e:
            raise e
        except Exception:
            raise SynapseError(400, "Unable to parse state")

        if self.hs.config.use_presence:
            yield self.presence_handler.set_state(user, state)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, request):
        return (200, {})


class PresenceListRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/presence/list/(?P<user_id>[^/]*)")

    def __init__(self, hs):
        super(PresenceListRestServlet, self).__init__(hs)
        self.presence_handler = hs.get_presence_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        if not self.hs.is_mine(user):
            raise SynapseError(400, "User not hosted on this Home Server")

        if requester.user != user:
            raise SynapseError(400, "Cannot get another user's presence list")

        presence = yield self.presence_handler.get_presence_list(
            observer_user=user, accepted=True
        )

        defer.returnValue((200, presence))

    @defer.inlineCallbacks
    def on_POST(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        if not self.hs.is_mine(user):
            raise SynapseError(400, "User not hosted on this Home Server")

        if requester.user != user:
            raise SynapseError(
                400, "Cannot modify another user's presence list")

        content = parse_json_object_from_request(request)

        if "invite" in content:
            for u in content["invite"]:
                if not isinstance(u, string_types):
                    raise SynapseError(400, "Bad invite value.")
                if len(u) == 0:
                    continue
                invited_user = UserID.from_string(u)
                yield self.presence_handler.send_presence_invite(
                    observer_user=user, observed_user=invited_user
                )

        if "drop" in content:
            for u in content["drop"]:
                if not isinstance(u, string_types):
                    raise SynapseError(400, "Bad drop value.")
                if len(u) == 0:
                    continue
                dropped_user = UserID.from_string(u)
                yield self.presence_handler.drop(
                    observer_user=user, observed_user=dropped_user
                )

        defer.returnValue((200, {}))

    def on_OPTIONS(self, request):
        return (200, {})


def register_servlets(hs, http_server):
    PresenceStatusRestServlet(hs).register(http_server)
    PresenceListRestServlet(hs).register(http_server)
