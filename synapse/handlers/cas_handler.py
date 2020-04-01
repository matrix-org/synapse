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
from typing import Dict, Optional, Tuple

from six.moves import urllib

from twisted.web.client import PartialDownloadError

from synapse.api.errors import Codes, LoginError
from synapse.http.site import SynapseRequest
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

    def _build_service_param(self, service_redirect_endpoint: str, **kwargs) -> str:
        """
        Generates a value to use as the "service" parameter when redirecting or
        querying the CAS service.

        Args:
            service_redirect_endpoint: The homeserver endpoint to redirect
                the client to after successful SSO negotiation.
            kwargs: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to use as a "service" parameter.
        """
        return "%s%s?%s" % (
            self._cas_service_url,
            service_redirect_endpoint,
            urllib.parse.urlencode(kwargs),
        )

    async def _validate_ticket(
        self, ticket: str, service_redirect_endpoint: str, client_redirect_url: str
    ) -> Tuple[str, Optional[str]]:
        """
        Validate a CAS ticket with the server, parse the response, and return the user and display name.

        Args:
            ticket: The CAS ticket from the client.
            service_redirect_endpoint: The homeserver endpoint that the client
                accessed to validate the ticket.
            client_redirect_url: The URL to redirect the client to after
                validation is done.
        """
        uri = self._cas_server_url + "/proxyValidate"
        args = {
            "ticket": ticket,
            "service": self._build_service_param(
                service_redirect_endpoint, redirectUrl=client_redirect_url
            ),
        }
        try:
            body = await self._http_client.get_raw(uri, args)
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response

        user, attributes = self._parse_cas_response(body)
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

        return user, displayname

    def _parse_cas_response(
        self, cas_response_body: str
    ) -> Tuple[str, Dict[str, Optional[str]]]:
        """
        Retrieve the user and other parameters from the CAS response.

        Args:
            cas_response_body: The response from the CAS query.

        Returns:
            A tuple of the user and a mapping of other attributes.
        """
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

    def get_redirect_url(self, service_redirect_endpoint: str, **kwargs) -> str:
        """
        Generates a URL to the CAS server where the client should be redirected.

        Args:
            service_redirect_endpoint: The homeserver endpoint to redirect
                the client to after successful SSO negotiation.
            kwargs: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to redirect the client to.
        """
        args = urllib.parse.urlencode(
            {"service": self._build_service_param(service_redirect_endpoint, **kwargs)}
        )

        return "%s/login?%s" % (self._cas_server_url, args)

    async def handle_ticket_for_login(
        self, request: SynapseRequest, client_redirect_url: str, ticket: str,
    ) -> None:
        """
        Called once the user has successfully authenticated with the SSO,
        validates a CAS ticket sent by the client and completes the login process.

        Registers the user if necessary, and then returns a redirect (with
        a login token) to the client.

        Args:
            request: the incoming request from the browser. We'll
                respond to it with a redirect.

            client_redirect_url: the redirect_url the client gave us when
                it first started the process.

            ticket: The CAS ticket provided by the client.
        """
        username, user_display_name = await self._validate_ticket(
            ticket, request.path, client_redirect_url
        )

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

    async def handle_ticket_for_ui_auth(
        self, request: SynapseRequest, ticket: str, session_id: str
    ) -> None:
        """
        Called once the user has successfully authenticated with the SSO,
        validates a CAS ticket sent by the client and completes user interactive
        authentication.

        If successful, this completes the SSO step of UI auth and returns a
        an HTML page to the client.

        Args:
            request: the incoming request from the browser.

            ticket: The CAS ticket provided by the client.

            session_id: The UI Auth session ID.
        """
        client_redirect_url = ""
        user, _ = await self._validate_ticket(ticket, request.path, client_redirect_url)

        localpart = map_username_to_mxid_localpart(user)
        user_id = UserID(localpart, self._hostname).to_string()
        registered_user_id = await self._auth_handler.check_user_exists(user_id)

        self._auth_handler.complete_sso_ui_auth(
            registered_user_id, session_id, request,
        )
