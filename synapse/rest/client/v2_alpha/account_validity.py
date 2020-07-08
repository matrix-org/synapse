# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from synapse.api.errors import AuthError, SynapseError
from synapse.http.server import respond_with_html
from synapse.http.servlet import RestServlet

from ._base import client_patterns

logger = logging.getLogger(__name__)


class AccountValidityRenewServlet(RestServlet):
    PATTERNS = client_patterns("/account_validity/renew$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(AccountValidityRenewServlet, self).__init__()

        self.hs = hs
        self.account_activity_handler = hs.get_account_validity_handler()
        self.auth = hs.get_auth()
        self.success_html = hs.config.account_validity.account_renewed_html_content
        self.failure_html = hs.config.account_validity.invalid_token_html_content

    async def on_GET(self, request):
        if b"token" not in request.args:
            raise SynapseError(400, "Missing renewal token")
        renewal_token = request.args[b"token"][0]

        token_valid = await self.account_activity_handler.renew_account(
            renewal_token.decode("utf8")
        )

        if token_valid:
            status_code = 200
            response = self.success_html
        else:
            status_code = 404
            response = self.failure_html

        respond_with_html(request, status_code, response)


class AccountValiditySendMailServlet(RestServlet):
    PATTERNS = client_patterns("/account_validity/send_mail$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(AccountValiditySendMailServlet, self).__init__()

        self.hs = hs
        self.account_activity_handler = hs.get_account_validity_handler()
        self.auth = hs.get_auth()
        self.account_validity = self.hs.config.account_validity

    async def on_POST(self, request):
        if not self.account_validity.renew_by_email_enabled:
            raise AuthError(
                403, "Account renewal via email is disabled on this server."
            )

        requester = await self.auth.get_user_by_req(request, allow_expired=True)
        user_id = requester.user.to_string()
        await self.account_activity_handler.send_renewal_email_to_user(user_id)

        return 200, {}


def register_servlets(hs, http_server):
    AccountValidityRenewServlet(hs).register(http_server)
    AccountValiditySendMailServlet(hs).register(http_server)
