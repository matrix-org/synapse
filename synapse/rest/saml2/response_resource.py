# -*- coding: utf-8 -*-
#
# Copyright 2018 New Vector Ltd
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

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import CodeMessageException
from synapse.http.server import wrap_html_request_handler
from synapse.http.servlet import parse_string
from synapse.rest.client.v1.login import SSOAuthHandler

logger = logging.getLogger(__name__)


class SAML2ResponseResource(Resource):
    """A Twisted web resource which handles the SAML response"""

    isLeaf = 1

    def __init__(self, hs):
        Resource.__init__(self)

        self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._sso_auth_handler = SSOAuthHandler(hs)

    def render_POST(self, request):
        self._async_render_POST(request)
        return NOT_DONE_YET

    @wrap_html_request_handler
    def _async_render_POST(self, request):
        resp_bytes = parse_string(request, 'SAMLResponse', required=True)
        relay_state = parse_string(request, 'RelayState', required=True)

        try:
            saml2_auth = self._saml_client.parse_authn_request_response(
                resp_bytes, saml2.BINDING_HTTP_POST,
            )
        except Exception as e:
            logger.warning("Exception parsing SAML2 response", exc_info=1)
            raise CodeMessageException(
                400, "Unable to parse SAML2 response: %s" % (e,),
            )

        if saml2_auth.not_signed:
            raise CodeMessageException(400, "SAML2 response was not signed")

        if "uid" not in saml2_auth.ava:
            raise CodeMessageException(400, "uid not in SAML2 response")

        username = saml2_auth.ava["uid"][0]

        displayName = saml2_auth.ava.get("displayName", [None])[0]
        return self._sso_auth_handler.on_successful_auth(
            username, request, relay_state,
            user_display_name=displayName,
        )
