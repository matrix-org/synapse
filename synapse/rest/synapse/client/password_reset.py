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
from typing import TYPE_CHECKING, Tuple

from twisted.web.server import Request

from synapse.api.errors import ThreepidValidationError
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.http.server import DirectServeHtmlResource
from synapse.http.servlet import parse_string
from synapse.util.stringutils import assert_valid_client_secret

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class PasswordResetSubmitTokenResource(DirectServeHtmlResource):
    """Handles 3PID validation token submission

    This resource gets mounted under /_synapse/client/password_reset/email/submit_token
    """

    isLeaf = 1

    def __init__(self, hs: "HomeServer"):
        """
        Args:
            hs: server
        """
        super().__init__()

        self.clock = hs.get_clock()
        self.store = hs.get_datastore()

        self._local_threepid_handling_disabled_due_to_email_config = (
            hs.config.local_threepid_handling_disabled_due_to_email_config
        )
        self._confirmation_email_template = (
            hs.config.email_password_reset_template_confirmation_html
        )
        self._email_password_reset_template_success_html = (
            hs.config.email_password_reset_template_success_html_content
        )
        self._failure_email_template = (
            hs.config.email_password_reset_template_failure_html
        )

        # This resource should not be mounted if threepid behaviour is not LOCAL
        assert hs.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL

    async def _async_render_GET(self, request: Request) -> Tuple[int, bytes]:
        sid = parse_string(request, "sid", required=True)
        token = parse_string(request, "token", required=True)
        client_secret = parse_string(request, "client_secret", required=True)
        assert_valid_client_secret(client_secret)

        # Show a confirmation page, just in case someone accidentally clicked this link when
        # they didn't mean to
        template_vars = {
            "sid": sid,
            "token": token,
            "client_secret": client_secret,
        }
        return (
            200,
            self._confirmation_email_template.render(**template_vars).encode("utf-8"),
        )

    async def _async_render_POST(self, request: Request) -> Tuple[int, bytes]:
        sid = parse_string(request, "sid", required=True)
        token = parse_string(request, "token", required=True)
        client_secret = parse_string(request, "client_secret", required=True)

        # Attempt to validate a 3PID session
        try:
            # Mark the session as valid
            next_link = await self.store.validate_threepid_session(
                sid, client_secret, token, self.clock.time_msec()
            )

            # Perform a 302 redirect if next_link is set
            if next_link:
                if next_link.startswith("file:///"):
                    logger.warning(
                        "Not redirecting to next_link as it is a local file: address"
                    )
                else:
                    next_link_bytes = next_link.encode("utf-8")
                    request.setHeader("Location", next_link_bytes)
                    return (
                        302,
                        (
                            b'You are being redirected to <a src="%s">%s</a>.'
                            % (next_link_bytes, next_link_bytes)
                        ),
                    )

            # Otherwise show the success template
            html_bytes = self._email_password_reset_template_success_html.encode(
                "utf-8"
            )
            status_code = 200
        except ThreepidValidationError as e:
            status_code = e.code

            # Show a failure page with a reason
            template_vars = {"failure_reason": e.msg}
            html_bytes = self._failure_email_template.render(**template_vars).encode(
                "utf-8"
            )

        return status_code, html_bytes
