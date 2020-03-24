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
import xml.etree.ElementTree as ET

from six.moves import urllib

from twisted.web.client import PartialDownloadError

from synapse.api.errors import Codes, LoginError
from synapse.http.servlet import parse_string
from synapse.types import UserID, map_username_to_mxid_localpart

logger = logging.getLogger(__name__)


class CasHandler:
    """
    Utility class for to handle the response from a CAS SSO service.

    Args:
        hs (synapse.server.HomeServer)
    """

    def __init__(self, hs):
        self._hostname = hs.hostname
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()

        self._cas_server_url = hs.config.cas_server_url
        self._cas_service_url = hs.config.cas_service_url
        self._cas_displayname_attribute = hs.config.cas_displayname_attribute
        self._cas_required_attributes = hs.config.cas_required_attributes

        self._http_client = hs.get_proxied_http_client()

        # cast to tuple for use with str.startswith
        self._whitelisted_sso_clients = tuple(hs.config.sso_client_whitelist)

    def _build_service_param(self, client_redirect_url):
        return "%s%s?redirectUrl=%s" % (
            self._cas_service_url,
            "/_matrix/client/r0/login/cas/ticket",
            urllib.parse.quote(client_redirect_url, safe=""),
        )

    def _handle_cas_response(self, request, cas_response_body, client_redirect_url):
        user, attributes = self._parse_cas_response(cas_response_body)
        displayname = attributes.pop(self._cas_displayname_attribute, None)

        for required_attribute, required_value in self._cas_required_attributes.items():
            # If required attribute was not in CAS Response - Forbidden
            if required_attribute not in attributes:
                raise LoginError(401, "Unauthorized", errcode=Codes.UNAUTHORIZED)

            # Also need to check value
            if required_value is not None:
                actual_value = attributes[required_attribute]
                # If required attribute value does not match expected - Forbidden
                if required_value != actual_value:
                    raise LoginError(401, "Unauthorized", errcode=Codes.UNAUTHORIZED)

        return self._on_successful_auth(user, request, client_redirect_url, displayname)

    def _parse_cas_response(self, cas_response_body):
        user = None
        attributes = {}
        try:
            root = ET.fromstring(cas_response_body)
            if not root.tag.endswith("serviceResponse"):
                raise Exception("root of CAS response is not serviceResponse")
            success = root[0].tag.endswith("authenticationSuccess")
            for child in root[0]:
                if child.tag.endswith("user"):
                    user = child.text
                if child.tag.endswith("attributes"):
                    for attribute in child:
                        # ElementTree library expands the namespace in
                        # attribute tags to the full URL of the namespace.
                        # We don't care about namespace here and it will always
                        # be encased in curly braces, so we remove them.
                        tag = attribute.tag
                        if "}" in tag:
                            tag = tag.split("}")[1]
                        attributes[tag] = attribute.text
            if user is None:
                raise Exception("CAS response does not contain user")
        except Exception:
            logger.exception("Error parsing CAS response")
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)
        if not success:
            raise LoginError(
                401, "Unsuccessful CAS response", errcode=Codes.UNAUTHORIZED
            )
        return user, attributes

    async def _on_successful_auth(
        self, username, request, client_redirect_url, user_display_name=None
    ):
        """Called once the user has successfully authenticated with the SSO.

        Registers the user if necessary, and then returns a redirect (with
        a login token) to the client.

        Args:
            username (unicode|bytes): the remote user id. We'll map this onto
                something sane for a MXID localpath.

            request (SynapseRequest): the incoming request from the browser. We'll
                respond to it with a redirect.

            client_redirect_url (unicode): the redirect_url the client gave us when
                it first started the process.

            user_display_name (unicode|None): if set, and we have to register a new user,
                we will set their displayname to this.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """
        localpart = map_username_to_mxid_localpart(username)
        user_id = UserID(localpart, self._hostname).to_string()
        registered_user_id = await self._auth_handler.check_user_exists(user_id)
        if not registered_user_id:
            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart, default_display_name=user_display_name
            )

        self._auth_handler.complete_sso_login(
            registered_user_id, request, client_redirect_url
        )

    def handle_redirect_request(self, client_redirect_url):
        args = urllib.parse.urlencode(
            {"service": self._build_service_param(client_redirect_url)}
        )

        return "%s/login?%s" % (self._cas_server_url, args)

    async def handle_ticket_request(self, request):
        client_redirect_url = parse_string(request, "redirectUrl", required=True)
        uri = self._cas_server_url + "/proxyValidate"
        args = {
            "ticket": parse_string(request, "ticket", required=True),
            "service": self._build_service_param(client_redirect_url),
        }
        try:
            body = await self._http_client.get_raw(uri, args)
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response

        return await self._handle_cas_response(request, body, client_redirect_url)
