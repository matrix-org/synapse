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
from typing import TYPE_CHECKING

import pkg_resources

from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.static import File

from synapse.api.errors import SynapseError
from synapse.handlers.sso import USERNAME_MAPPING_SESSION_COOKIE_NAME
from synapse.http.server import DirectServeHtmlResource, DirectServeJsonResource
from synapse.http.servlet import parse_string
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer


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

        session_id = request.getCookie(USERNAME_MAPPING_SESSION_COOKIE_NAME)
        if not session_id:
            raise SynapseError(code=400, msg="missing session_id")

        is_available = await self._sso_handler.check_username_availability(
            localpart, session_id.decode("ascii", errors="replace")
        )
        return 200, {"available": is_available}


class SubmitResource(DirectServeHtmlResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

    async def _async_render_POST(self, request: SynapseRequest):
        localpart = parse_string(request, "username", required=True)

        session_id = request.getCookie(USERNAME_MAPPING_SESSION_COOKIE_NAME)
        if not session_id:
            raise SynapseError(code=400, msg="missing session_id")

        await self._sso_handler.handle_submit_username_request(
            request, localpart, session_id.decode("ascii", errors="replace")
        )
