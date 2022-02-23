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
import re
from typing import TYPE_CHECKING, Callable, Dict, Optional, Set, Tuple

import attr
import saml2
import saml2.response
from saml2.client import Saml2Client

from synapse.api.errors import SynapseError
from synapse.config import ConfigError
from synapse.handlers.sso import MappingException, UserAttributes
from synapse.http.servlet import parse_string
from synapse.http.site import SynapseRequest
from synapse.module_api import ModuleApi
from synapse.types import (
    UserID,
    map_username_to_mxid_localpart,
    mxid_localpart_allowed_characters,
)
from synapse.util.iterutils import chunk_seq

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, auto_attribs=True)
class Saml2SessionData:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time: int
    # The user interactive authentication session ID associated with this SAML
    # session (or None if this SAML session is for an initial login).
    ui_auth_session_id: Optional[str] = None


class SamlHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self._saml_client = Saml2Client(hs.config.saml2.saml2_sp_config)
        self._saml_idp_entityid = hs.config.saml2.saml2_idp_entityid

        self._saml2_session_lifetime = hs.config.saml2.saml2_session_lifetime
        self._grandfathered_mxid_source_attribute = (
            hs.config.saml2.saml2_grandfathered_mxid_source_attribute
        )
        self._saml2_attribute_requirements = hs.config.saml2.attribute_requirements

        # plugin to do custom mapping from saml response to mxid
        self._user_mapping_provider = hs.config.saml2.saml2_user_mapping_provider_class(
            hs.config.saml2.saml2_user_mapping_provider_config,
            ModuleApi(hs, hs.get_auth_handler()),
        )

        # identifier for the external_ids table
        self.idp_id = "saml"

        # user-facing name of this auth provider
        self.idp_name = "SAML"

        # we do not currently support icons/brands for SAML auth, but this is required by
        # the SsoIdentityProvider protocol type.
        self.idp_icon = None
        self.idp_brand = None

        # a map from saml session id to Saml2SessionData object
        self._outstanding_requests_dict: Dict[str, Saml2SessionData] = {}

        self._sso_handler = hs.get_sso_handler()
        self._sso_handler.register_identity_provider(self)

    async def handle_redirect_request(
        self,
        request: SynapseRequest,
        client_redirect_url: Optional[bytes],
        ui_auth_session_id: Optional[str] = None,
    ) -> str:
        """Handle an incoming request to /login/sso/redirect

        Args:
            request: the incoming HTTP request
            client_redirect_url: the URL that we should redirect the
                client to after login (or None for UI Auth).
            ui_auth_session_id: The session ID of the ongoing UI Auth (or
                None if this is a login).

        Returns:
            URL to redirect to
        """
        if not client_redirect_url:
            # Some SAML identity providers (e.g. Google) require a
            # RelayState parameter on requests, so pass in a dummy redirect URL
            # (which will never get used).
            client_redirect_url = b"unused"

        reqid, info = self._saml_client.prepare_for_authenticate(
            entityid=self._saml_idp_entityid, relay_state=client_redirect_url
        )

        # Since SAML sessions timeout it is useful to log when they were created.
        logger.info("Initiating a new SAML session: %s" % (reqid,))

        now = self.clock.time_msec()
        self._outstanding_requests_dict[reqid] = Saml2SessionData(
            creation_time=now,
            ui_auth_session_id=ui_auth_session_id,
        )

        for key, value in info["headers"]:
            if key == "Location":
                return value

        # this shouldn't happen!
        raise Exception("prepare_for_authenticate didn't return a Location header")

    async def handle_saml_response(self, request: SynapseRequest) -> None:
        """Handle an incoming request to /_synapse/client/saml2/authn_response

        Args:
            request: the incoming request from the browser. We'll
                respond to it with a redirect.

        Returns:
            Completes once we have handled the request.
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
        except saml2.response.UnsolicitedResponse as e:
            # the pysaml2 library helpfully logs an ERROR here, but neglects to log
            # the session ID. I don't really want to put the full text of the exception
            # in the (user-visible) exception message, so let's log the exception here
            # so we can track down the session IDs later.
            logger.warning(str(e))
            self._sso_handler.render_error(
                request, "unsolicited_response", "Unexpected SAML2 login."
            )
            return
        except Exception as e:
            self._sso_handler.render_error(
                request,
                "invalid_response",
                "Unable to parse SAML2 response: %s." % (e,),
            )
            return

        if saml2_auth.not_signed:
            self._sso_handler.render_error(
                request, "unsigned_respond", "SAML2 response was not signed."
            )
            return

        logger.debug("SAML2 response: %s", saml2_auth.origxml)

        await self._handle_authn_response(request, saml2_auth, relay_state)

    async def _handle_authn_response(
        self,
        request: SynapseRequest,
        saml2_auth: saml2.response.AuthnResponse,
        relay_state: str,
    ) -> None:
        """Handle an AuthnResponse, having parsed it from the request params

        Assumes that the signature on the response object has been checked. Maps
        the user onto an MXID, registering them if necessary, and returns a response
        to the browser.

        Args:
            request: the incoming request from the browser. We'll respond to it with an
                HTML page or a redirect
            saml2_auth: the parsed AuthnResponse object
            relay_state: the RelayState query param, which encodes the URI to rediret
               back to
        """

        for assertion in saml2_auth.assertions:
            # kibana limits the length of a log field, whereas this is all rather
            # useful, so split it up.
            count = 0
            for part in chunk_seq(str(assertion), 10000):
                logger.info(
                    "SAML2 assertion: %s%s", "(%i)..." % (count,) if count else "", part
                )
                count += 1

        logger.info("SAML2 mapped attributes: %s", saml2_auth.ava)

        current_session = self._outstanding_requests_dict.pop(
            saml2_auth.in_response_to, None
        )

        # first check if we're doing a UIA
        if current_session and current_session.ui_auth_session_id:
            try:
                remote_user_id = self._remote_id_from_saml_response(saml2_auth, None)
            except MappingException as e:
                logger.exception("Failed to extract remote user id from SAML response")
                self._sso_handler.render_error(request, "mapping_error", str(e))
                return

            return await self._sso_handler.complete_sso_ui_auth_request(
                self.idp_id,
                remote_user_id,
                current_session.ui_auth_session_id,
                request,
            )

        # otherwise, we're handling a login request.

        # Ensure that the attributes of the logged in user meet the required
        # attributes.
        if not self._sso_handler.check_required_attributes(
            request, saml2_auth.ava, self._saml2_attribute_requirements
        ):
            return

        # Call the mapper to register/login the user
        try:
            await self._complete_saml_login(saml2_auth, request, relay_state)
        except MappingException as e:
            logger.exception("Could not map user")
            self._sso_handler.render_error(request, "mapping_error", str(e))

    async def _complete_saml_login(
        self,
        saml2_auth: saml2.response.AuthnResponse,
        request: SynapseRequest,
        client_redirect_url: str,
    ) -> None:
        """
        Given a SAML response, complete the login flow

        Retrieves the remote user ID, registers the user if necessary, and serves
        a redirect back to the client with a login-token.

        Args:
            saml2_auth: The parsed SAML2 response.
            request: The request to respond to
            client_redirect_url: The redirect URL passed in by the client.

        Raises:
            MappingException if there was a problem mapping the response to a user.
            RedirectException: some mapping providers may raise this if they need
                to redirect to an interstitial page.
        """
        remote_user_id = self._remote_id_from_saml_response(
            saml2_auth, client_redirect_url
        )

        async def saml_response_to_remapped_user_attributes(
            failures: int,
        ) -> UserAttributes:
            """
            Call the mapping provider to map a SAML response to user attributes and coerce the result into the standard form.

            This is backwards compatibility for abstraction for the SSO handler.
            """
            # Call the mapping provider.
            result = self._user_mapping_provider.saml_response_to_user_attributes(
                saml2_auth, failures, client_redirect_url
            )
            # Remap some of the results.
            return UserAttributes(
                localpart=result.get("mxid_localpart"),
                display_name=result.get("displayname"),
                emails=result.get("emails", []),
            )

        async def grandfather_existing_users() -> Optional[str]:
            # backwards-compatibility hack: see if there is an existing user with a
            # suitable mapping from the uid
            if (
                self._grandfathered_mxid_source_attribute
                and self._grandfathered_mxid_source_attribute in saml2_auth.ava
            ):
                attrval = saml2_auth.ava[self._grandfathered_mxid_source_attribute][0]
                user_id = UserID(
                    map_username_to_mxid_localpart(attrval), self.server_name
                ).to_string()

                logger.debug(
                    "Looking for existing account based on mapped %s %s",
                    self._grandfathered_mxid_source_attribute,
                    user_id,
                )

                users = await self.store.get_users_by_id_case_insensitive(user_id)
                if users:
                    registered_user_id = list(users.keys())[0]
                    logger.info("Grandfathering mapping to %s", registered_user_id)
                    return registered_user_id

            return None

        await self._sso_handler.complete_sso_login_request(
            self.idp_id,
            remote_user_id,
            request,
            client_redirect_url,
            saml_response_to_remapped_user_attributes,
            grandfather_existing_users,
        )

    def _remote_id_from_saml_response(
        self,
        saml2_auth: saml2.response.AuthnResponse,
        client_redirect_url: Optional[str],
    ) -> str:
        """Extract the unique remote id from a SAML2 AuthnResponse

        Args:
            saml2_auth: The parsed SAML2 response.
            client_redirect_url: The redirect URL passed in by the client.
        Returns:
            remote user id

        Raises:
            MappingException if there was an error extracting the user id
        """
        # It's not obvious why we need to pass in the redirect URI to the mapping
        # provider, but we do :/
        remote_user_id = self._user_mapping_provider.get_remote_user_id(
            saml2_auth, client_redirect_url
        )

        if not remote_user_id:
            raise MappingException(
                "Failed to extract remote user id from SAML response"
            )

        return remote_user_id

    def expire_sessions(self) -> None:
        expire_before = self.clock.time_msec() - self._saml2_session_lifetime
        to_expire = set()
        for reqid, data in self._outstanding_requests_dict.items():
            if data.creation_time < expire_before:
                to_expire.add(reqid)
        for reqid in to_expire:
            logger.debug("Expiring session id %s", reqid)
            del self._outstanding_requests_dict[reqid]


DOT_REPLACE_PATTERN = re.compile(
    "[^%s]" % (re.escape("".join(mxid_localpart_allowed_characters)),)
)


def dot_replace_for_mxid(username: str) -> str:
    """Replace any characters which are not allowed in Matrix IDs with a dot."""
    username = username.lower()
    username = DOT_REPLACE_PATTERN.sub(".", username)

    # regular mxids aren't allowed to start with an underscore either
    username = re.sub("^_", "", username)
    return username


MXID_MAPPER_MAP: Dict[str, Callable[[str], str]] = {
    "hexencode": map_username_to_mxid_localpart,
    "dotreplace": dot_replace_for_mxid,
}


@attr.s(auto_attribs=True)
class SamlConfig:
    mxid_source_attribute: str
    mxid_mapper: Callable[[str], str]


class DefaultSamlMappingProvider:
    __version__ = "0.0.1"

    def __init__(self, parsed_config: SamlConfig, module_api: ModuleApi):
        """The default SAML user mapping provider

        Args:
            parsed_config: Module configuration
            module_api: module api proxy
        """
        self._mxid_source_attribute = parsed_config.mxid_source_attribute
        self._mxid_mapper = parsed_config.mxid_mapper

        self._grandfathered_mxid_source_attribute = (
            module_api._hs.config.saml2.saml2_grandfathered_mxid_source_attribute
        )

    def get_remote_user_id(
        self, saml_response: saml2.response.AuthnResponse, client_redirect_url: str
    ) -> str:
        """Extracts the remote user id from the SAML response"""
        try:
            return saml_response.ava["uid"][0]
        except KeyError:
            logger.warning("SAML2 response lacks a 'uid' attestation")
            raise MappingException("'uid' not in SAML2 response")

    def saml_response_to_user_attributes(
        self,
        saml_response: saml2.response.AuthnResponse,
        failures: int,
        client_redirect_url: str,
    ) -> dict:
        """Maps some text from a SAML response to attributes of a new user

        Args:
            saml_response: A SAML auth response object

            failures: How many times a call to this function with this
                saml_response has resulted in a failure

            client_redirect_url: where the client wants to redirect to

        Returns:
            dict: A dict containing new user attributes. Possible keys:
                * mxid_localpart (str): Required. The localpart of the user's mxid
                * displayname (str): The displayname of the user
                * emails (list[str]): Any emails for the user
        """
        try:
            mxid_source = saml_response.ava[self._mxid_source_attribute][0]
        except KeyError:
            logger.warning(
                "SAML2 response lacks a '%s' attestation",
                self._mxid_source_attribute,
            )
            raise SynapseError(
                400, "%s not in SAML2 response" % (self._mxid_source_attribute,)
            )

        # Use the configured mapper for this mxid_source
        localpart = self._mxid_mapper(mxid_source)

        # Append suffix integer if last call to this function failed to produce
        # a usable mxid.
        localpart += str(failures) if failures else ""

        # Retrieve the display name from the saml response
        # If displayname is None, the mxid_localpart will be used instead
        displayname = saml_response.ava.get("displayName", [None])[0]

        # Retrieve any emails present in the saml response
        emails = saml_response.ava.get("email", [])

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
            "emails": emails,
        }

    @staticmethod
    def parse_config(config: dict) -> SamlConfig:
        """Parse the dict provided by the homeserver's config
        Args:
            config: A dictionary containing configuration options for this provider
        Returns:
            SamlConfig: A custom config object for this module
        """
        # Parse config options and use defaults where necessary
        mxid_source_attribute = config.get("mxid_source_attribute", "uid")
        mapping_type = config.get("mxid_mapping", "hexencode")

        # Retrieve the associating mapping function
        try:
            mxid_mapper = MXID_MAPPER_MAP[mapping_type]
        except KeyError:
            raise ConfigError(
                "saml2_config.user_mapping_provider.config: '%s' is not a valid "
                "mxid_mapping value" % (mapping_type,)
            )

        return SamlConfig(mxid_source_attribute, mxid_mapper)

    @staticmethod
    def get_saml_attributes(config: SamlConfig) -> Tuple[Set[str], Set[str]]:
        """Returns the required attributes of a SAML

        Args:
            config: A SamlConfig object containing configuration params for this provider

        Returns:
            The first set equates to the saml auth response
                attributes that are required for the module to function, whereas the
                second set consists of those attributes which can be used if
                available, but are not necessary
        """
        return {"uid", config.mxid_source_attribute}, {"displayName", "email"}
