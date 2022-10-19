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
from typing import TYPE_CHECKING, Dict, List, Optional
from xml.etree import ElementTree as ET

import attr

from twisted.web.client import PartialDownloadError

from synapse.api.errors import HttpResponseException
from synapse.handlers.sso import MappingException, UserAttributes
from synapse.http.site import SynapseRequest
from synapse.types import UserID, map_username_to_mxid_localpart

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class CasError(Exception):
    """Used to catch errors when validating the CAS ticket."""

    def __init__(self, error: str, error_description: Optional[str] = None):
        self.error = error
        self.error_description = error_description

    def __str__(self) -> str:
        if self.error_description:
            return f"{self.error}: {self.error_description}"
        return self.error


@attr.s(slots=True, frozen=True, auto_attribs=True)
class CasResponse:
    username: str
    attributes: Dict[str, List[Optional[str]]]


class CasHandler:
    """
    Utility class for to handle the response from a CAS SSO service.

    Args:
        hs
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self._hostname = hs.hostname
        self._store = hs.get_datastores().main
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()

        self._cas_server_url = hs.config.cas.cas_server_url
        self._cas_service_url = hs.config.cas.cas_service_url
        self._cas_displayname_attribute = hs.config.cas.cas_displayname_attribute
        self._cas_required_attributes = hs.config.cas.cas_required_attributes

        self._http_client = hs.get_proxied_http_client()

        # identifier for the external_ids table
        self.idp_id = "cas"

        # user-facing name of this auth provider
        self.idp_name = "CAS"

        # we do not currently support brands/icons for CAS auth, but this is required by
        # the SsoIdentityProvider protocol type.
        self.idp_icon = None
        self.idp_brand = None

        self._sso_handler = hs.get_sso_handler()

        self._sso_handler.register_identity_provider(self)

    def _build_service_param(self, args: Dict[str, str]) -> str:
        """
        Generates a value to use as the "service" parameter when redirecting or
        querying the CAS service.

        Args:
            args: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to use as a "service" parameter.
        """
        return "%s?%s" % (
            self._cas_service_url,
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
                Should be the same as those passed to `handle_redirect_request`.

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
            # Assertion is for mypy's benefit. Error.response is Optional[bytes],
            # but a PartialDownloadError should always have a non-None response.
            assert pde.response is not None
            body = pde.response
        except HttpResponseException as e:
            description = (
                'Authorization server responded with a "{status}" error '
                "while exchanging the authorization code."
            ).format(status=e.code)
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
        attributes: Dict[str, List[Optional[str]]] = {}
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
                    attributes.setdefault(tag, []).append(attribute.text)

        # Ensure a user was found.
        if user is None:
            raise CasError("no_user", "CAS response does not contain user")

        return CasResponse(user, attributes)

    async def handle_redirect_request(
        self,
        request: SynapseRequest,
        client_redirect_url: Optional[bytes],
        ui_auth_session_id: Optional[str] = None,
    ) -> str:
        """Generates a URL for the CAS server where the client should be redirected.

        Args:
            request: the incoming HTTP request
            client_redirect_url: the URL that we should redirect the
                client to after login (or None for UI Auth).
            ui_auth_session_id: The session ID of the ongoing UI Auth (or
                None if this is a login).

        Returns:
            URL to redirect to
        """

        if ui_auth_session_id:
            service_args = {"session": ui_auth_session_id}
        else:
            assert client_redirect_url
            service_args = {"redirectUrl": client_redirect_url.decode("utf8")}

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

        # first check if we're doing a UIA
        if session:
            return await self._sso_handler.complete_sso_ui_auth_request(
                self.idp_id,
                cas_response.username,
                session,
                request,
            )

        # otherwise, we're handling a login request.

        # Ensure that the attributes of the logged in user meet the required
        # attributes.
        if not self._sso_handler.check_required_attributes(
            request, cas_response.attributes, self._cas_required_attributes
        ):
            return

        # Call the mapper to register/login the user

        # If this not a UI auth request than there must be a redirect URL.
        assert client_redirect_url is not None

        try:
            await self._complete_cas_login(cas_response, request, client_redirect_url)
        except MappingException as e:
            logger.exception("Could not map user")
            self._sso_handler.render_error(request, "mapping_error", str(e))

    async def _complete_cas_login(
        self,
        cas_response: CasResponse,
        request: SynapseRequest,
        client_redirect_url: str,
    ) -> None:
        """
        Given a CAS response, complete the login flow

        Retrieves the remote user ID, registers the user if necessary, and serves
        a redirect back to the client with a login-token.

        Args:
            cas_response: The parsed CAS response.
            request: The request to respond to
            client_redirect_url: The redirect URL passed in by the client.

        Raises:
            MappingException if there was a problem mapping the response to a user.
            RedirectException: some mapping providers may raise this if they need
                to redirect to an interstitial page.
        """
        # Note that CAS does not support a mapping provider, so the logic is hard-coded.
        localpart = map_username_to_mxid_localpart(cas_response.username)

        async def cas_response_to_user_attributes(failures: int) -> UserAttributes:
            """
            Map from CAS attributes to user attributes.
            """
            # Due to the grandfathering logic matching any previously registered
            # mxids it isn't expected for there to be any failures.
            if failures:
                raise RuntimeError("CAS is not expected to de-duplicate Matrix IDs")

            # Arbitrarily use the first attribute found.
            display_name = cas_response.attributes.get(
                self._cas_displayname_attribute, [None]
            )[0]

            return UserAttributes(localpart=localpart, display_name=display_name)

        async def grandfather_existing_users() -> Optional[str]:
            # Since CAS did not always use the user_external_ids table, always
            # to attempt to map to existing users.
            user_id = UserID(localpart, self._hostname).to_string()

            logger.debug(
                "Looking for existing account based on mapped %s",
                user_id,
            )

            users = await self._store.get_users_by_id_case_insensitive(user_id)
            if users:
                registered_user_id = list(users.keys())[0]
                logger.info("Grandfathering mapping to %s", registered_user_id)
                return registered_user_id

            return None

        await self._sso_handler.complete_sso_login_request(
            self.idp_id,
            cas_response.username,
            request,
            client_redirect_url,
            cas_response_to_user_attributes,
            grandfather_existing_users,
        )
