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

from six.moves import urllib

from twisted.web.client import PartialDownloadError

from synapse.api.errors import Codes, LoginError
from synapse.http.servlet import parse_string
from synapse.rest.client.v1.login import SSOAuthHandler
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)


class OAuth2Handler:
    def __init__(self, hs):
        # config
        self.public_baseurl = hs.config.public_baseurl.encode("ascii")
        self.oauth2_server_authorization_url = hs.config.oauth2_server_authorization_url.encode(
            "ascii"
        )
        self.oauth2_server_token_url = hs.config.oauth2_server_token_url
        self.oauth2_server_userinfo_url = hs.config.oauth2_server_userinfo_url
        self.oauth2_client_id = hs.config.oauth2_client_id
        self.oauth2_client_secret = hs.config.oauth2_client_secret
        self.oauth2_scope = "openid"
        self.oauth2_response_type = "code"
        self.oauth2_response_mode = "query"

        # state
        self.nonces = ExpiringCache(
            cache_name="oauth_nonces",
            clock=hs.get_clock(),
            expiry_ms=5 * 60 * 1000,  # 5 minutes
            reset_expiry_on_get=False,
        )

        # tools
        self._sso_auth_handler = SSOAuthHandler(hs)
        self._http_client = hs.get_proxied_http_client()

    def handle_redirect_request(self, client_redirect_url):
        """Handle an incoming request to /login/sso/redirect

        Args:
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            bytes: URL to redirect to
        """

        oauth2_nonce = random_string(12)
        self.nonces[oauth2_nonce] = {"redirectUrl": client_redirect_url}

        service_param = urllib.parse.urlencode(
            {
                b"redirect_uri": self.get_server_redirect_url(),
                b"client_id": self.oauth2_client_id,
                b"scope": self.oauth2_scope,
                b"response_type": self.oauth2_response_type,
                b"response_mode": self.oauth2_response_mode,
                b"state": oauth2_nonce,
            }
        ).encode("ascii")
        return b"%s?%s" % (self.oauth2_server_authorization_url, service_param)

    async def handle_oauth2_response(self, request):
        """Handle an incoming request to /_matrix/oauth2/response

        Args:
            request (SynapseRequest): the incoming request from the browser. We'll
                respond to it with a redirect.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """
        oauth2_code = parse_string(request, "code", required=True)
        oauth2_state = parse_string(request, "state", required=False)

        # validate state
        if oauth2_state not in self.nonces:
            raise LoginError(
                400, "Invalid or expire state passed", errcode=Codes.UNAUTHORIZED
            )

        client_redirect_url = self.nonces[oauth2_state].pop("redirectUrl").decode()
        logging.warning(client_redirect_url)

        access_token = await self.get_access_token(oauth2_code)
        userinfo = await self.get_userinfo(access_token)

        user = "sso_" + userinfo.get("sub")
        displayname = userinfo.get("preferred_username")

        result = await self._sso_auth_handler.on_successful_auth(
            user, request, client_redirect_url, displayname
        )
        return result

    async def get_access_token(self, oauth2_code):
        args = {
            "client_id": self.oauth2_client_id,
            "client_secret": self.oauth2_client_secret,
            "code": oauth2_code,
            "grant_type": "authorization_code",
            "redirect_uri": self.get_server_redirect_url(),
        }

        try:
            body = await self._http_client.post_urlencoded_get_json(
                self.oauth2_server_token_url, args
            )
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response

        access_token = body.get("access_token")
        return access_token

    async def get_userinfo(self, access_token):
        headers = {
            "Authorization": ["Bearer " + access_token],
        }

        try:
            userinfo = await self._http_client.get_json(
                self.oauth2_server_userinfo_url, {}, headers
            )
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            userinfo = pde.response

        return userinfo

    def get_server_redirect_url(self):
        return self.public_baseurl + b"_matrix/client/r0/login/oauth/response"
