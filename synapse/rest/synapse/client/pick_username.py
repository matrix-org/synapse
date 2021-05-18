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
from typing import TYPE_CHECKING, List

from twisted.web.resource import Resource
from twisted.web.server import Request

from synapse.api.errors import SynapseError
from synapse.handlers.sso import get_username_mapping_session_cookie_from_request
from synapse.http.server import (
    DirectServeHtmlResource,
    DirectServeJsonResource,
    respond_with_html,
)
from synapse.http.servlet import parse_boolean, parse_string
from synapse.http.site import SynapseRequest
from synapse.util.templates import build_jinja_env

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def pick_username_resource(hs: "HomeServer") -> Resource:
    """Factory method to generate the username picker resource.

    This resource gets mounted under /_synapse/client/pick_username and has two
       children:

      * "account_details": renders the form and handles the POSTed response
      * "check": a JSON endpoint which checks if a userid is free.
    """

    res = Resource()
    res.putChild(b"account_details", AccountDetailsResource(hs))
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


class AccountDetailsResource(DirectServeHtmlResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

        def template_search_dirs():
            if hs.config.sso.sso_template_dir:
                yield hs.config.sso.sso_template_dir
            yield hs.config.sso.default_template_dir

        self._jinja_env = build_jinja_env(template_search_dirs(), hs.config)

    async def _async_render_GET(self, request: Request) -> None:
        try:
            session_id = get_username_mapping_session_cookie_from_request(request)
            session = self._sso_handler.get_mapping_session(session_id)
        except SynapseError as e:
            logger.warning("Error fetching session: %s", e)
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return

        idp_id = session.auth_provider_id
        template_params = {
            "idp": self._sso_handler.get_identity_providers()[idp_id],
            "user_attributes": {
                "display_name": session.display_name,
                "emails": session.emails,
            },
        }

        template = self._jinja_env.get_template("sso_auth_account_details.html")
        html = template.render(template_params)
        respond_with_html(request, 200, html)

    async def _async_render_POST(self, request: SynapseRequest):
        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        try:
            session_id = get_username_mapping_session_cookie_from_request(request)
        except SynapseError as e:
            logger.warning("Error fetching session cookie: %s", e)
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return

        try:
            localpart = parse_string(request, "username", required=True)
            use_display_name = parse_boolean(request, "use_display_name", default=False)

            try:
                emails_to_use = [
                    val.decode("utf-8") for val in request.args.get(b"use_email", [])
                ]  # type: List[str]
            except ValueError:
                raise SynapseError(400, "Query parameter use_email must be utf-8")
        except SynapseError as e:
            logger.warning("[session %s] bad param: %s", session_id, e)
            self._sso_handler.render_error(request, "bad_param", e.msg, code=e.code)
            return

        await self._sso_handler.handle_submit_username_request(
            request, session_id, localpart, use_display_name, emails_to_use
        )
