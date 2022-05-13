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

from twisted.web.server import Request

from synapse.api.constants import LoginType
from synapse.api.errors import LoginError, SynapseError
from synapse.api.urls import CLIENT_API_PREFIX
from synapse.http.server import HttpServer, respond_with_html
from synapse.http.servlet import RestServlet, parse_string
from synapse.http.site import SynapseRequest

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
        self.recaptcha_template = hs.config.captcha.recaptcha_template
        self.terms_template = hs.config.consent.terms_template
        self.registration_token_template = (
            hs.config.registration.registration_token_template
        )
        self.success_template = hs.config.registration.fallback_success_template

    async def on_GET(self, request: SynapseRequest, stagetype: str) -> None:
        session = parse_string(request, "session")
        if not session:
            raise SynapseError(400, "No session supplied")

        if stagetype == LoginType.RECAPTCHA:
            html = self.recaptcha_template.render(
                session=session,
                myurl="%s/v3/auth/%s/fallback/web"
                % (CLIENT_API_PREFIX, LoginType.RECAPTCHA),
                sitekey=self.hs.config.captcha.recaptcha_public_key,
            )
        elif stagetype == LoginType.TERMS:
            html = self.terms_template.render(
                session=session,
                terms_url="%s_matrix/consent?v=%s"
                % (
                    self.hs.config.server.public_baseurl,
                    self.hs.config.consent.user_consent_version,
                ),
                myurl="%s/v3/auth/%s/fallback/web"
                % (CLIENT_API_PREFIX, LoginType.TERMS),
            )

        elif stagetype == LoginType.SSO:
            # Display a confirmation page which prompts the user to
            # re-authenticate with their SSO provider.
            html = await self.auth_handler.start_sso_ui_auth(request, session)

        elif stagetype == LoginType.REGISTRATION_TOKEN:
            html = self.registration_token_template.render(
                session=session,
                myurl=f"{CLIENT_API_PREFIX}/r0/auth/{LoginType.REGISTRATION_TOKEN}/fallback/web",
            )

        else:
            raise SynapseError(404, "Unknown auth stage type")

        # Render the HTML and return.
        respond_with_html(request, 200, html)
        return None

    async def on_POST(self, request: Request, stagetype: str) -> None:

        session = parse_string(request, "session")
        if not session:
            raise SynapseError(400, "No session supplied")

        if stagetype == LoginType.RECAPTCHA:
            response = parse_string(request, "g-recaptcha-response")

            if not response:
                raise SynapseError(400, "No captcha response supplied")

            authdict = {"response": response, "session": session}

            try:
                await self.auth_handler.add_oob_auth(
                    LoginType.RECAPTCHA, authdict, request.getClientAddress().host
                )
            except LoginError as e:
                # Authentication failed, let user try again
                html = self.recaptcha_template.render(
                    session=session,
                    myurl="%s/v3/auth/%s/fallback/web"
                    % (CLIENT_API_PREFIX, LoginType.RECAPTCHA),
                    sitekey=self.hs.config.captcha.recaptcha_public_key,
                    error=e.msg,
                )
            else:
                # No LoginError was raised, so authentication was successful
                html = self.success_template.render()

        elif stagetype == LoginType.TERMS:
            authdict = {"session": session}

            try:
                await self.auth_handler.add_oob_auth(
                    LoginType.TERMS, authdict, request.getClientAddress().host
                )
            except LoginError as e:
                # Authentication failed, let user try again
                html = self.terms_template.render(
                    session=session,
                    terms_url="%s_matrix/consent?v=%s"
                    % (
                        self.hs.config.server.public_baseurl,
                        self.hs.config.consent.user_consent_version,
                    ),
                    myurl="%s/v3/auth/%s/fallback/web"
                    % (CLIENT_API_PREFIX, LoginType.TERMS),
                    error=e.msg,
                )
            else:
                # No LoginError was raised, so authentication was successful
                html = self.success_template.render()

        elif stagetype == LoginType.SSO:
            # The SSO fallback workflow should not post here,
            raise SynapseError(404, "Fallback SSO auth does not support POST requests.")

        elif stagetype == LoginType.REGISTRATION_TOKEN:
            token = parse_string(request, "token", required=True)
            authdict = {"session": session, "token": token}

            try:
                await self.auth_handler.add_oob_auth(
                    LoginType.REGISTRATION_TOKEN,
                    authdict,
                    request.getClientAddress().host,
                )
            except LoginError as e:
                html = self.registration_token_template.render(
                    session=session,
                    myurl=f"{CLIENT_API_PREFIX}/r0/auth/{LoginType.REGISTRATION_TOKEN}/fallback/web",
                    error=e.msg,
                )
            else:
                html = self.success_template.render()

        else:
            raise SynapseError(404, "Unknown auth stage type")

        # Render the HTML and return.
        respond_with_html(request, 200, html)
        return None


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    AuthRestServlet(hs).register(http_server)
