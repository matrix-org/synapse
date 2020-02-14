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

import attr
import saml2
from saml2.client import Saml2Client

from synapse.api.errors import SynapseError
from synapse.http.servlet import parse_string
from synapse.rest.client.v1.login import SSOAuthHandler

logger = logging.getLogger(__name__)


class SamlHandler:
    def __init__(self, hs):
        self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._sso_auth_handler = SSOAuthHandler(hs)

        # a map from saml session id to Saml2SessionData object
        self._outstanding_requests_dict = {}

        self._clock = hs.get_clock()
        self._saml2_session_lifetime = hs.config.saml2_session_lifetime

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

        now = self._clock.time_msec()
        self._outstanding_requests_dict[reqid] = Saml2SessionData(creation_time=now)

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

        # expire outstanding sessions before parse_authn_request_response checks
        # the dict.
        self.expire_sessions()

        try:
            saml2_auth = self._saml_client.parse_authn_request_response(
                resp_bytes,
                saml2.BINDING_HTTP_POST,
                outstanding=self._outstanding_requests_dict,
            )
        except Exception as e:
            logger.warning("Exception parsing SAML2 response: %s", e)
            raise SynapseError(400, "Unable to parse SAML2 response: %s" % (e,))

        if saml2_auth.not_signed:
            logger.warning("SAML2 response was not signed")
            raise SynapseError(400, "SAML2 response was not signed")

        if "uid" not in saml2_auth.ava:
            logger.warning("SAML2 response lacks a 'uid' attestation")
            raise SynapseError(400, "uid not in SAML2 response")

        self._outstanding_requests_dict.pop(saml2_auth.in_response_to, None)

        username = saml2_auth.ava["uid"][0]
        displayName = saml2_auth.ava.get("displayName", [None])[0]

        return self._sso_auth_handler.on_successful_auth(
            username, request, relay_state, user_display_name=displayName
        )

    def expire_sessions(self):
        expire_before = self._clock.time_msec() - self._saml2_session_lifetime
        to_expire = set()
        for reqid, data in self._outstanding_requests_dict.items():
            if data.creation_time < expire_before:
                to_expire.add(reqid)
        for reqid in to_expire:
            logger.debug("Expiring session id %s", reqid)
            del self._outstanding_requests_dict[reqid]


@attr.s
class Saml2SessionData:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time = attr.ib()
