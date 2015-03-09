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

"""This module contains REST servlets to do with registration: /register"""
from twisted.internet import defer

from base import AppServiceRestServlet, as_path_pattern
from synapse.api.errors import CodeMessageException, SynapseError
from synapse.storage.appservice import ApplicationService

import json
import logging

logger = logging.getLogger(__name__)


class RegisterRestServlet(AppServiceRestServlet):
    """Handles AS registration with the home server.
    """

    PATTERN = as_path_pattern("/register$")

    @defer.inlineCallbacks
    def on_POST(self, request):
        params = _parse_json(request)

        # sanity check required params
        try:
            as_token = params["as_token"]
            as_url = params["url"]
            if (not isinstance(as_token, basestring) or
                    not isinstance(as_url, basestring)):
                raise ValueError
        except (KeyError, ValueError):
            raise SynapseError(
                400, "Missed required keys: as_token(str) / url(str)."
            )

        try:
            app_service = ApplicationService(
                as_token, as_url, params["namespaces"]
            )
        except ValueError as e:
            raise SynapseError(400, e.message)

        app_service = yield self.handler.register(app_service)
        hs_token = app_service.hs_token

        defer.returnValue((200, {
            "hs_token": hs_token
        }))


class UnregisterRestServlet(AppServiceRestServlet):
    """Handles AS registration with the home server.
    """

    PATTERN = as_path_pattern("/unregister$")

    def on_POST(self, request):
        params = _parse_json(request)
        try:
            as_token = params["as_token"]
            if not isinstance(as_token, basestring):
                raise ValueError
        except (KeyError, ValueError):
            raise SynapseError(400, "Missing required key: as_token(str)")

        yield self.handler.unregister(as_token)

        raise CodeMessageException(500, "Not implemented")


def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.")
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.")


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)
    UnregisterRestServlet(hs).register(http_server)
