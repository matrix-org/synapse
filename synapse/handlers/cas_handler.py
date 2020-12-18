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
import urllib.parse
from typing import TYPE_CHECKING, Dict, Optional
from xml.etree import ElementTree as ET

import attr

from twisted.web.client import PartialDownloadError

from synapse.api.errors import HttpResponseException
from synapse.http.site import SynapseRequest
from synapse.types import UserID, map_username_to_mxid_localpart

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


class CasError(Exception):
    """Used to catch errors when validating the CAS ticket.
    """

    def __init__(self, error, error_description=None):
        self.error = error
        self.error_description = error_description

    def __str__(self):
        if self.error_description:
            return "{}: {}".format(self.error, self.error_description)
        return self.error


@attr.s(slots=True, frozen=True)
class CasResponse:
    username = attr.ib(type=str)
    attributes = attr.ib(type=Dict[str, Optional[str]])


class CasHandler:
    """
    Utility class for to handle the response from a CAS SSO service.

    Args:
        hs
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self._hostname = hs.hostname
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()

        self._cas_server_url = hs.config.cas_server_url
        self._cas_service_url = hs.config.cas_service_url
        self._cas_displayname_attribute = hs.config.cas_displayname_attribute
        self._cas_required_attributes = hs.config.cas_required_attributes

        self._http_client = hs.get_proxied_http_client()

        self._sso_handler = hs.get_sso_handler()

    def _build_service_param(self, args: Dict[str, str]) -> str:
        """
        Generates a value to use as the "service" parameter when redirecting or
        querying the CAS service.

        Args:
            args: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to use as a "service" parameter.
        """
        return "%s%s?%s" % (
            self._cas_service_url,
            "/_matrix/client/r0/login/cas/ticket",
            urllib.parse.urlencode(args),
        )

    async def _validate_ticket(
        self, ticket: str, service_args: Dict[str, str]
    ) -> CasResponse:
        """
        Validate a CAS ticket with the server, and return the parsed the response.

        Args:
            ticket: The CAS ticket from the client.
            service_args: Additional arguments to include in the service URL.
                Should be the same as those passed to `get_redirect_url`.

        Raises:
            CasError: If there's an error parsing the CAS response.

        Returns:
            The parsed CAS response.
        """
        uri = self._cas_server_url + "/proxyValidate"
        args = {
            "ticket": ticket,
            "service": self._build_service_param(service_args),
        }
        try:
            body = await self._http_client.get_raw(uri, args)
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response
        except HttpResponseException as e:
            description = (
                (
                    'Authorization server responded with a "{status}" error '
                    "while exchanging the authorization code."
                ).format(status=e.code),
            )
            raise CasError("server_error", description) from e

        return self._parse_cas_response(body)

    def _parse_cas_response(self, cas_response_body: bytes) -> CasResponse:
        """
        Retrieve the user and other parameters from the CAS response.

        Args:
            cas_response_body: The response from the CAS query.

        Raises:
            CasError: If there's an error parsing the CAS response.

        Returns:
            The parsed CAS response.
        """

        # Ensure the response is valid.
        root = ET.fromstring(cas_response_body)
        if not root.tag.endswith("serviceResponse"):
            raise CasError(
                "missing_service_response",
                "root of CAS response is not serviceResponse",
            )

        success = root[0].tag.endswith("authenticationSuccess")
        if not success:
            raise CasError("unsucessful_response", "Unsuccessful CAS response")

        # Iterate through the nodes and pull out the user and any extra attributes.
        user = None
        attributes = {}
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

        # Ensure a user was found.
        if user is None:
            raise CasError("no_user", "CAS response does not contain user")

        return CasResponse(user, attributes)

    def get_redirect_url(self, service_args: Dict[str, str]) -> str:
        """
        Generates a URL for the CAS server where the client should be redirected.

        Args:
            service_args: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to redirect the client to.
        """
        args = urllib.parse.urlencode(
            {"service": self._build_service_param(service_args)}
        )

        return "%s/login?%s" % (self._cas_server_url, args)

    async def handle_ticket(
        self,
        request: SynapseRequest,
        ticket: str,
        client_redirect_url: Optional[str],
        session: Optional[str],
    ) -> None:
        """
        Called once the user has successfully authenticated with the SSO.
        Validates a CAS ticket sent by the client and completes the auth process.

        If the user interactive authentication session is provided, marks the
        UI Auth session as complete, then returns an HTML page notifying the
        user they are done.

        Otherwise, this registers the user if necessary, and then returns a
        redirect (with a login token) to the client.

        Args:
            request: the incoming request from the browser. We'll
                respond to it with a redirect or an HTML page.

            ticket: The CAS ticket provided by the client.

            client_redirect_url: the redirectUrl parameter from the `/cas/ticket` HTTP request, if given.
                This should be the same as the redirectUrl from the original `/login/sso/redirect` request.

            session: The session parameter from the `/cas/ticket` HTTP request, if given.
                This should be the UI Auth session id.
        """
        args = {}
        if client_redirect_url:
            args["redirectUrl"] = client_redirect_url
        if session:
            args["session"] = session

        try:
            cas_response = await self._validate_ticket(ticket, args)
        except CasError as e:
            logger.exception("Could not validate ticket")
            self._sso_handler.render_error(request, e.error, e.error_description, 401)
            return

        await self._handle_cas_response(
            request, cas_response, client_redirect_url, session
        )

    async def _handle_cas_response(
        self,
        request: SynapseRequest,
        cas_response: CasResponse,
        client_redirect_url: Optional[str],
        session: Optional[str],
    ) -> None:
        """Handle a CAS response to a ticket request.

        Assumes that the response has been validated. Maps the user onto an MXID,
        registering them if necessary, and returns a response to the browser.

        Args:
            request: the incoming request from the browser. We'll respond to it with an
                HTML page or a redirect

            cas_response: The parsed CAS response.

            client_redirect_url: the redirectUrl parameter from the `/cas/ticket` HTTP request, if given.
                This should be the same as the redirectUrl from the original `/login/sso/redirect` request.

            session: The session parameter from the `/cas/ticket` HTTP request, if given.
                This should be the UI Auth session id.
        """

        # Ensure that the attributes of the logged in user meet the required
        # attributes.
        for required_attribute, required_value in self._cas_required_attributes.items():
            # If required attribute was not in CAS Response - Forbidden
            if required_attribute not in cas_response.attributes:
                self._sso_handler.render_error(
                    request,
                    "unauthorised",
                    "You are not authorised to log in here.",
                    401,
                )
                return

            # Also need to check value
            if required_value is not None:
                actual_value = cas_response.attributes[required_attribute]
                # If required attribute value does not match expected - Forbidden
                if required_value != actual_value:
                    self._sso_handler.render_error(
                        request,
                        "unauthorised",
                        "You are not authorised to log in here.",
                        401,
                    )
                    return

        # Pull out the user-agent and IP from the request.
        user_agent = request.get_user_agent("")
        ip_address = self.hs.get_ip_from_request(request)

        # Get the matrix ID from the CAS username.
        user_id = await self._map_cas_user_to_matrix_user(
            cas_response, user_agent, ip_address
        )

        if session:
            await self._auth_handler.complete_sso_ui_auth(
                user_id, session, request,
            )
        else:
            # If this not a UI auth request than there must be a redirect URL.
            assert client_redirect_url

            await self._auth_handler.complete_sso_login(
                user_id, request, client_redirect_url
            )

    async def _map_cas_user_to_matrix_user(
        self, cas_response: CasResponse, user_agent: str, ip_address: str,
    ) -> str:
        """
        Given a CAS username, retrieve the user ID for it and possibly register the user.

        Args:
            cas_response: The parsed CAS response.
            user_agent: The user agent of the client making the request.
            ip_address: The IP address of the client making the request.

        Returns:
             The user ID associated with this response.
        """

        localpart = map_username_to_mxid_localpart(cas_response.username)
        user_id = UserID(localpart, self._hostname).to_string()
        registered_user_id = await self._auth_handler.check_user_exists(user_id)

        displayname = cas_response.attributes.get(self._cas_displayname_attribute, None)

        # If the user does not exist, register it.
        if not registered_user_id:
            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart,
                default_display_name=displayname,
                user_agent_ips=[(user_agent, ip_address)],
            )

        return registered_user_id
