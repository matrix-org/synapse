# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.constants import LoginType
from synapse.api.errors import SynapseError
from synapse.api.urls import CLIENT_API_PREFIX
from synapse.http.server import respond_with_html
from synapse.http.servlet import RestServlet, parse_string

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class AuthRestServlet(RestServlet):
    """
    Handles Client / Server API authentication in any situations where it
    cannot be handled in the normal flow (with requests to the same endpoint).
    Current use is for web fallback auth.
    """

    PATTERNS = client_patterns(r"/auth/(?P<stagetype>[\w\.]*)/fallback/web")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self.recaptcha_template = hs.config.recaptcha_template
        self.terms_template = hs.config.terms_template
        self.success_template = hs.config.fallback_success_template

    async def on_GET(self, request, stagetype):
        session = parse_string(request, "session")
        if not session:
            raise SynapseError(400, "No session supplied")

        if stagetype == LoginType.RECAPTCHA:
            html = self.recaptcha_template.render(
                session=session,
                myurl="%s/r0/auth/%s/fallback/web"
                % (CLIENT_API_PREFIX, LoginType.RECAPTCHA),
                sitekey=self.hs.config.recaptcha_public_key,
            )
        elif stagetype == LoginType.TERMS:
            html = self.terms_template.render(
                session=session,
                terms_url="%s_matrix/consent?v=%s"
                % (self.hs.config.public_baseurl, self.hs.config.user_consent_version),
                myurl="%s/r0/auth/%s/fallback/web"
                % (CLIENT_API_PREFIX, LoginType.TERMS),
            )

        elif stagetype == LoginType.SSO:
            # Display a confirmation page which prompts the user to
            # re-authenticate with their SSO provider.
            html = await self.auth_handler.start_sso_ui_auth(request, session)

        else:
            raise SynapseError(404, "Unknown auth stage type")

        # Render the HTML and return.
        respond_with_html(request, 200, html)
        return None

    async def on_POST(self, request, stagetype):

        session = parse_string(request, "session")
        if not session:
            raise SynapseError(400, "No session supplied")

        if stagetype == LoginType.RECAPTCHA:
            response = parse_string(request, "g-recaptcha-response")

            if not response:
                raise SynapseError(400, "No captcha response supplied")

            authdict = {"response": response, "session": session}

            success = await self.auth_handler.add_oob_auth(
                LoginType.RECAPTCHA, authdict, request.getClientIP()
            )

            if success:
                html = self.success_template.render()
            else:
                html = self.recaptcha_template.render(
                    session=session,
                    myurl="%s/r0/auth/%s/fallback/web"
                    % (CLIENT_API_PREFIX, LoginType.RECAPTCHA),
                    sitekey=self.hs.config.recaptcha_public_key,
                )
        elif stagetype == LoginType.TERMS:
            authdict = {"session": session}

            success = await self.auth_handler.add_oob_auth(
                LoginType.TERMS, authdict, request.getClientIP()
            )

            if success:
                html = self.success_template.render()
            else:
                html = self.terms_template.render(
                    session=session,
                    terms_url="%s_matrix/consent?v=%s"
                    % (
                        self.hs.config.public_baseurl,
                        self.hs.config.user_consent_version,
                    ),
                    myurl="%s/r0/auth/%s/fallback/web"
                    % (CLIENT_API_PREFIX, LoginType.TERMS),
                )
        elif stagetype == LoginType.SSO:
            # The SSO fallback workflow should not post here,
            raise SynapseError(404, "Fallback SSO auth does not support POST requests.")
        else:
            raise SynapseError(404, "Unknown auth stage type")

        # Render the HTML and return.
        respond_with_html(request, 200, html)
        return None


def register_servlets(hs, http_server):
    AuthRestServlet(hs).register(http_server)
