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

from synapse.api.constants import LoginType
from synapse.api.errors import SynapseError
from synapse.api.urls import CLIENT_API_PREFIX
from synapse.handlers.auth import SUCCESS_TEMPLATE
from synapse.http.server import finish_request
from synapse.http.servlet import RestServlet, parse_string

from ._base import client_patterns

logger = logging.getLogger(__name__)

RECAPTCHA_TEMPLATE = """
<html>
<head>
<title>Authentication</title>
<meta name='viewport' content='width=device-width, initial-scale=1,
    user-scalable=no, minimum-scale=1.0, maximum-scale=1.0'>
<script src="https://www.recaptcha.net/recaptcha/api.js"
    async defer></script>
<script src="//code.jquery.com/jquery-1.11.2.min.js"></script>
<link rel="stylesheet" href="/_matrix/static/client/register/style.css">
<script>
function captchaDone() {
    $('#registrationForm').submit();
}
</script>
</head>
<body>
<form id="registrationForm" method="post" action="%(myurl)s">
    <div>
        <p>
        Hello! We need to prevent computer programs and other automated
        things from creating accounts on this server.
        </p>
        <p>
        Please verify that you're not a robot.
        </p>
        <input type="hidden" name="session" value="%(session)s" />
        <div class="g-recaptcha"
            data-sitekey="%(sitekey)s"
            data-callback="captchaDone">
        </div>
        <noscript>
        <input type="submit" value="All Done" />
        </noscript>
        </div>
    </div>
</form>
</body>
</html>
"""

TERMS_TEMPLATE = """
<html>
<head>
<title>Authentication</title>
<meta name='viewport' content='width=device-width, initial-scale=1,
    user-scalable=no, minimum-scale=1.0, maximum-scale=1.0'>
<link rel="stylesheet" href="/_matrix/static/client/register/style.css">
</head>
<body>
<form id="registrationForm" method="post" action="%(myurl)s">
    <div>
        <p>
            Please click the button below if you agree to the
            <a href="%(terms_url)s">privacy policy of this homeserver.</a>
        </p>
        <input type="hidden" name="session" value="%(session)s" />
        <input type="submit" value="Agree" />
    </div>
</form>
</body>
</html>
"""


class AuthRestServlet(RestServlet):
    """
    Handles Client / Server API authentication in any situations where it
    cannot be handled in the normal flow (with requests to the same endpoint).
    Current use is for web fallback auth.
    """

    PATTERNS = client_patterns(r"/auth/(?P<stagetype>[\w\.]*)/fallback/web")

    def __init__(self, hs):
        super(AuthRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()

        # SSO configuration.
        self._saml_enabled = hs.config.saml2_enabled
        if self._saml_enabled:
            self._saml_handler = hs.get_saml_handler()

    def on_GET(self, request, stagetype):
        session = parse_string(request, "session")
        if not session:
            raise SynapseError(400, "No session supplied")

        if stagetype == LoginType.RECAPTCHA:
            html = RECAPTCHA_TEMPLATE % {
                "session": session,
                "myurl": "%s/r0/auth/%s/fallback/web"
                % (CLIENT_API_PREFIX, LoginType.RECAPTCHA),
                "sitekey": self.hs.config.recaptcha_public_key,
            }
        elif stagetype == LoginType.TERMS:
            html = TERMS_TEMPLATE % {
                "session": session,
                "terms_url": "%s_matrix/consent?v=%s"
                % (self.hs.config.public_baseurl, self.hs.config.user_consent_version),
                "myurl": "%s/r0/auth/%s/fallback/web"
                % (CLIENT_API_PREFIX, LoginType.TERMS),
            }

        elif stagetype == LoginType.SSO and self._saml_enabled:
            # Display a confirmation page which prompts the user to
            # re-authenticate with their SSO provider.
            client_redirect_url = ""
            sso_redirect_url = self._saml_handler.handle_redirect_request(
                client_redirect_url, session
            )
            html = self.auth_handler.start_sso_ui_auth(sso_redirect_url)
        else:
            raise SynapseError(404, "Unknown auth stage type")

        # Render the HTML and return.
        html_bytes = html.encode("utf8")
        request.setResponseCode(200)
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%d" % (len(html_bytes),))

        request.write(html_bytes)
        finish_request(request)
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
                LoginType.RECAPTCHA, authdict, self.hs.get_ip_from_request(request)
            )

            if success:
                html = SUCCESS_TEMPLATE
            else:
                html = RECAPTCHA_TEMPLATE % {
                    "session": session,
                    "myurl": "%s/r0/auth/%s/fallback/web"
                    % (CLIENT_API_PREFIX, LoginType.RECAPTCHA),
                    "sitekey": self.hs.config.recaptcha_public_key,
                }
        elif stagetype == LoginType.TERMS:
            authdict = {"session": session}

            success = await self.auth_handler.add_oob_auth(
                LoginType.TERMS, authdict, self.hs.get_ip_from_request(request)
            )

            if success:
                html = SUCCESS_TEMPLATE
            else:
                html = TERMS_TEMPLATE % {
                    "session": session,
                    "terms_url": "%s_matrix/consent?v=%s"
                    % (
                        self.hs.config.public_baseurl,
                        self.hs.config.user_consent_version,
                    ),
                    "myurl": "%s/r0/auth/%s/fallback/web"
                    % (CLIENT_API_PREFIX, LoginType.TERMS),
                }
        elif stagetype == LoginType.SSO:
            # The SSO fallback workflow should not post here,
            raise SynapseError(404, "Fallback SSO auth does not support POST requests.")
        else:
            raise SynapseError(404, "Unknown auth stage type")

        # Render the HTML and return.
        html_bytes = html.encode("utf8")
        request.setResponseCode(200)
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%d" % (len(html_bytes),))

        request.write(html_bytes)
        finish_request(request)
        return None

    def on_OPTIONS(self, _):
        return 200, {}


def register_servlets(hs, http_server):
    AuthRestServlet(hs).register(http_server)
