# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import saml2
from saml2.client import Saml2Client

from synapse.api.errors import CodeMessageException
from synapse.http.servlet import parse_string
from synapse.rest.client.v1.login import SSOAuthHandler

logger = logging.getLogger(__name__)


class Saml2Handler:
    def __init__(self, hs):
        self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._sso_auth_handler = SSOAuthHandler(hs)

    def handle_redirect_request(self, client_redirect_url):
        """Handle an incoming request to /login/sso/redirect

        Args:
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            bytes: URL to redirect to
        """
        reqid, info = self._saml_client.prepare_for_authenticate(
            relay_state=client_redirect_url
        )

        for key, value in info["headers"]:
            if key == "Location":
                return value

        # this shouldn't happen!
        raise Exception("prepare_for_authenticate didn't return a Location header")

    def handle_saml_response(self, request):
        """Handle an incoming request to /_matrix/saml2/authn_response

        Args:
            request (SynapseRequest): the incoming request from the browser. We'll
                respond to it with a redirect.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """
        resp_bytes = parse_string(request, "SAMLResponse", required=True)
        relay_state = parse_string(request, "RelayState", required=True)

        try:
            saml2_auth = self._saml_client.parse_authn_request_response(
                resp_bytes, saml2.BINDING_HTTP_POST
            )
        except Exception as e:
            logger.warning("Exception parsing SAML2 response", exc_info=1)
            raise CodeMessageException(400, "Unable to parse SAML2 response: %s" % (e,))

        if saml2_auth.not_signed:
            raise CodeMessageException(400, "SAML2 response was not signed")

        if "uid" not in saml2_auth.ava:
            raise CodeMessageException(400, "uid not in SAML2 response")

        username = saml2_auth.ava["uid"][0]

        displayName = saml2_auth.ava.get("displayName", [None])[0]

        return self._sso_auth_handler.on_successful_auth(
            username, request, relay_state, user_display_name=displayName
        )
