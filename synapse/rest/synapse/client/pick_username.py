# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING

import pkg_resources

from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.static import File

from synapse.api.errors import SynapseError
from synapse.handlers.sso import get_username_mapping_session_cookie_from_request
from synapse.http.server import DirectServeHtmlResource, DirectServeJsonResource
from synapse.http.servlet import parse_string
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def pick_username_resource(hs: "HomeServer") -> Resource:
    """Factory method to generate the username picker resource.

    This resource gets mounted under /_synapse/client/pick_username. The top-level
    resource is just a File resource which serves up the static files in the resources
    "res" directory, but it has a couple of children:

    * "submit", which does the mechanics of registering the new user, and redirects the
      browser back to the client URL

    * "check": checks if a userid is free.
    """

    # XXX should we make this path customisable so that admins can restyle it?
    base_path = pkg_resources.resource_filename("synapse", "res/username_picker")

    res = File(base_path)
    res.putChild(b"submit", SubmitResource(hs))
    res.putChild(b"check", AvailabilityCheckResource(hs))

    return res


class AvailabilityCheckResource(DirectServeJsonResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

    async def _async_render_GET(self, request: Request):
        localpart = parse_string(request, "username", required=True)

        session_id = get_username_mapping_session_cookie_from_request(request)

        is_available = await self._sso_handler.check_username_availability(
            localpart, session_id
        )
        return 200, {"available": is_available}


class SubmitResource(DirectServeHtmlResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

    async def _async_render_POST(self, request: SynapseRequest):
        try:
            session_id = get_username_mapping_session_cookie_from_request(request)
        except SynapseError as e:
            logger.warning("Error fetching session cookie: %s", e)
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return

        try:
            localpart = parse_string(request, "username", required=True)
        except SynapseError as e:
            logger.warning("[session %s] bad param: %s", session_id, e)
            self._sso_handler.render_error(request, "bad_param", e.msg, code=e.code)
            return

        await self._sso_handler.handle_submit_username_request(
            request, localpart, session_id
        )
