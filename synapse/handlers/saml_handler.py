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
import re
from typing import Tuple

import attr
import saml2
import saml2.response
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.s_utils import status_message_factory, success_status_factory
from saml2.samlp import STATUS_REQUEST_DENIED, STATUS_SUCCESS

from synapse.api.errors import SynapseError
from synapse.config import ConfigError
from synapse.http.servlet import parse_string
from synapse.module_api import ModuleApi
from synapse.rest.client.v1.login import SSOAuthHandler
from synapse.types import (
    UserID,
    map_username_to_mxid_localpart,
    mxid_localpart_allowed_characters,
)
from synapse.util.async_helpers import Linearizer
from synapse.util.iterutils import chunk_seq

logger = logging.getLogger(__name__)


@attr.s
class Saml2SessionData:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time = attr.ib()


class SamlHandler:
    def __init__(self, hs):
        self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()
        self._sso_auth_handler = SSOAuthHandler(hs)
        self._registration_handler = hs.get_registration_handler()

        self._clock = hs.get_clock()
        self._datastore = hs.get_datastore()
        self._hostname = hs.hostname
        self._saml2_session_lifetime = hs.config.saml2_session_lifetime
        self._grandfathered_mxid_source_attribute = (
            hs.config.saml2_grandfathered_mxid_source_attribute
        )

        # plugin to do custom mapping from saml response to mxid
        self._user_mapping_provider = hs.config.saml2_user_mapping_provider_class(
            hs.config.saml2_user_mapping_provider_config,
            ModuleApi(hs, hs.get_auth_handler()),
        )

        # identifier for the external_ids table
        self._auth_provider_id = "saml"

        # a map from saml session id to Saml2SessionData object
        self._outstanding_requests_dict = {}

        # a lock on the mappings
        self._mapping_lock = Linearizer(name="saml_mapping", clock=self._clock)

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

    # User should have only one local session to only one entity
    # But in case of crash we may have multiple sessions stored in the
    # local cache. In that case we select the last session and remove
    # other ones.
    def _find_session_from_user(self, username):
        subjects = self._saml_client.users.subjects()
        sessions = []
        # Find all sessions for a specific subject
        for name_id in subjects:
            # We should always have one source only
            for source in self._saml_client.users.sources(name_id):
                info = self._saml_client.users.get_info_from(name_id, source)
                # If the username is found, append the session info
                if (
                    "ava" in info
                    and "uid" in info["ava"]
                    and username in info["ava"]["uid"]
                ):
                    info["entity"] = source
                    sessions.append(info)

        sessions.sort(key=lambda i: i["not_on_or_after"])
        try:
            # Retrieve last session
            last_session = sessions.pop()
            # We should have only one session active for one person
            # This should never match but removing these staled sessions anyway
            [self._saml_client.local_logout(session["name_id"]) for session in sessions]
            return last_session
        except IndexError:
            return None

    def _find_mxid_from_name_id(self, name_id):
        try:
            attributes = self._saml_client.users.get_identity(name_id)
            for attribute in attributes:
                if self._mxid_source_attribute in attribute:
                    return "@%s:%s" % (
                        attribute[self._mxid_source_attribute][0],
                        self._auth_handler.hs.hostname,
                    )
        except Exception:
            pass
        return None

    async def _logout(self, mxid):
        # first delete all of the user's devices
        await self._device_handler.delete_all_devices_for_user(mxid)

        # .. and then delete any access tokens which weren't associated with
        # devices.
        await self._auth_handler.delete_access_tokens_for_user(mxid)

    # Example: https://github.com/IdentityPython/pysaml2/blob/master/example/sp-wsgi/sp.py
    def create_logout_request(self, user, access_token):
        """Create a SAML logout request using HTTP redirect binding

        Returns:
            bytes: URL to redirect to
        """
        logger.info("Creating SAML logout request for %s", user)
        try:
            localpart = UserID.from_string(user).localpart
            logger.debug("User localpart is %s", localpart)

            session = self._find_session_from_user(localpart)
            # The user probally logged in via m.login.password
            if session is None:
                return False
            logger.debug("User session is %s", session)

            # Creating a logout request through redirect
            response = self._saml_client.do_logout(
                session["name_id"],
                [session["entity"]],
                reason="/_matrix/client/r0/logout requested",
                expire=None,
                expected_binding=BINDING_HTTP_REDIRECT,
            )

            # Logging out from multiple entities is not supported
            binding, http_info = next(iter(response.values()))
            logger.debug("SAML binding %s, http_info %s", binding, http_info)

            redirect_url = next(
                header[1] for header in http_info["headers"] if header[0] == "Location"
            )
            if not redirect_url:
                raise RuntimeError("missing Location header")

            return redirect_url

        except Exception as e:
            raise SynapseError(
                500, "error while creating SAML logout request: %s" % (e,)
            )

    async def handle_logout_request(self, request):
        """Handle an incoming LogoutRequest to /_matrix/saml2/logout

        Args:
            request (bytes): a SAML LogoutRequest

        Returns:
            bytes: URL to redirect to
        """
        saml_req_encoded = parse_string(request, "SAMLRequest", required=True)
        relay_state = parse_string(request, "RelayState")
        # TODO: sign LogoutRequest responses if required by the IdP
        # sign = parse_string(request, "SigAlg")
        # sign_alg = parse_string(request, "Signature")

        saml_req = self._saml_client.parse_logout_request(
            saml_req_encoded, BINDING_HTTP_REDIRECT
        )
        name_id = saml_req.message.name_id
        mxid = self._find_mxid_from_name_id(name_id)

        # Logout from matrix
        if mxid:
            await self._logout(mxid)

        # Logout from the local SAML cache
        try:

            if self._saml_client.local_logout(name_id):
                status = success_status_factory()
            else:
                status = status_message_factory("Server error", STATUS_REQUEST_DENIED)
        except KeyError:
            status = status_message_factory("Server error", STATUS_REQUEST_DENIED)

        # Prepare SAML LogoutResponse using HTTP_REDIRECT
        response = self._saml_client.create_logout_response(
            saml_req.message, [BINDING_HTTP_REDIRECT], status
        )
        rinfo = self._saml_client.response_args(
            saml_req.message, [BINDING_HTTP_REDIRECT]
        )

        rfinal = self._saml_client.apply_binding(
            rinfo["binding"], response, rinfo["destination"], relay_state, response=True
        )

        # Return the redirect_url
        for key, value in rfinal["headers"]:
            if key == "Location":
                return value

        # this shouldn't happen!
        raise Exception("create_logout_response didn't return a Location header")

    def handle_logout_response(self, request):
        """
            Handle an incoming LogoutResponse to /_matrix/saml2/logout
        """
        resp_bytes = parse_string(request, "SAMLResponse", required=True)
        try:
            resp_saml = self._saml_client.parse_logout_request_response(
                resp_bytes, BINDING_HTTP_REDIRECT
            )
            logger.info("Received SAML logout response %s", resp_saml)
            if resp_saml.response.status.status_code.value == STATUS_SUCCESS:
                # Remove user from local SAML cache
                status = self._saml_client.state[resp_saml.in_response_to]
                logger.debug("Status of the SAML cached logout request %s", status)
                self._saml_client.local_logout(decode(status["name_id"]))
                return
            raise SynapseError(
                500,
                "Could not logout from SAML: %s" % (resp_saml.response.status.message,),
            )
        except Exception as e:
            raise SynapseError(400, "Unable to parse SAML2 response: %s" % (e,))

    async def handle_saml_response(self, request):
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

        user_id = await self._map_saml_response_to_user(resp_bytes, relay_state)
        self._sso_auth_handler.complete_sso_login(user_id, request, relay_state)

    async def _map_saml_response_to_user(self, resp_bytes, client_redirect_url):
        try:
            saml2_auth = self._saml_client.parse_authn_request_response(
                resp_bytes,
                BINDING_HTTP_POST,
                outstanding=self._outstanding_requests_dict,
            )
        except Exception as e:
            logger.warning("Exception parsing SAML2 response: %s", e)
            raise SynapseError(400, "Unable to parse SAML2 response: %s" % (e,))

        if saml2_auth.not_signed:
            logger.warning("SAML2 response was not signed")
            raise SynapseError(400, "SAML2 response was not signed")

        logger.debug("SAML2 response: %s", saml2_auth.origxml)
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

        self._outstanding_requests_dict.pop(saml2_auth.in_response_to, None)

        remote_user_id = self._user_mapping_provider.get_remote_user_id(
            saml2_auth, client_redirect_url
        )

        if not remote_user_id:
            raise Exception("Failed to extract remote user id from SAML response")

        with (await self._mapping_lock.queue(self._auth_provider_id)):
            # first of all, check if we already have a mapping for this user
            logger.info(
                "Looking for existing mapping for user %s:%s",
                self._auth_provider_id,
                remote_user_id,
            )
            registered_user_id = await self._datastore.get_user_by_external_id(
                self._auth_provider_id, remote_user_id
            )
            if registered_user_id is not None:
                logger.info("Found existing mapping %s", registered_user_id)
                return registered_user_id

            # backwards-compatibility hack: see if there is an existing user with a
            # suitable mapping from the uid
            if (
                self._grandfathered_mxid_source_attribute
                and self._grandfathered_mxid_source_attribute in saml2_auth.ava
            ):
                attrval = saml2_auth.ava[self._grandfathered_mxid_source_attribute][0]
                user_id = UserID(
                    map_username_to_mxid_localpart(attrval), self._hostname
                ).to_string()
                logger.info(
                    "Looking for existing account based on mapped %s %s",
                    self._grandfathered_mxid_source_attribute,
                    user_id,
                )

                users = await self._datastore.get_users_by_id_case_insensitive(user_id)
                if users:
                    registered_user_id = list(users.keys())[0]
                    logger.info("Grandfathering mapping to %s", registered_user_id)
                    await self._datastore.record_user_external_id(
                        self._auth_provider_id, remote_user_id, registered_user_id
                    )
                    return registered_user_id

            # Map saml response to user attributes using the configured mapping provider
            for i in range(1000):
                attribute_dict = self._user_mapping_provider.saml_response_to_user_attributes(
                    saml2_auth, i, client_redirect_url=client_redirect_url,
                )

                logger.debug(
                    "Retrieved SAML attributes from user mapping provider: %s "
                    "(attempt %d)",
                    attribute_dict,
                    i,
                )

                localpart = attribute_dict.get("mxid_localpart")
                if not localpart:
                    logger.error(
                        "SAML mapping provider plugin did not return a "
                        "mxid_localpart object"
                    )
                    raise SynapseError(500, "Error parsing SAML2 response")

                displayname = attribute_dict.get("displayname")

                # Check if this mxid already exists
                if not await self._datastore.get_users_by_id_case_insensitive(
                    UserID(localpart, self._hostname).to_string()
                ):
                    # This mxid is free
                    break
            else:
                # Unable to generate a username in 1000 iterations
                # Break and return error to the user
                raise SynapseError(
                    500, "Unable to generate a Matrix ID from the SAML response"
                )

            logger.info("Mapped SAML user to local part %s", localpart)

            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart, default_display_name=displayname
            )

            await self._datastore.record_user_external_id(
                self._auth_provider_id, remote_user_id, registered_user_id
            )

            return registered_user_id

    def expire_sessions(self):
        expire_before = self._clock.time_msec() - self._saml2_session_lifetime
        to_expire = set()
        for reqid, data in self._outstanding_requests_dict.items():
            if data.creation_time < expire_before:
                to_expire.add(reqid)
        for reqid in to_expire:
            logger.debug("Expiring session id %s", reqid)
            del self._outstanding_requests_dict[reqid]


DOT_REPLACE_PATTERN = re.compile(
    ("[^%s]" % (re.escape("".join(mxid_localpart_allowed_characters)),))
)


def dot_replace_for_mxid(username: str) -> str:
    username = username.lower()
    username = DOT_REPLACE_PATTERN.sub(".", username)

    # regular mxids aren't allowed to start with an underscore either
    username = re.sub("^_", "", username)
    return username


MXID_MAPPER_MAP = {
    "hexencode": map_username_to_mxid_localpart,
    "dotreplace": dot_replace_for_mxid,
}


@attr.s
class SamlConfig(object):
    mxid_source_attribute = attr.ib()
    mxid_mapper = attr.ib()


class DefaultSamlMappingProvider(object):
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
            module_api._hs.config.saml2_grandfathered_mxid_source_attribute
        )

    def get_remote_user_id(
        self, saml_response: saml2.response.AuthnResponse, client_redirect_url: str
    ):
        """Extracts the remote user id from the SAML response"""
        try:
            return saml_response.ava["uid"][0]
        except KeyError:
            logger.warning("SAML2 response lacks a 'uid' attestation")
            raise SynapseError(400, "'uid' not in SAML2 response")

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
        """
        try:
            mxid_source = saml_response.ava[self._mxid_source_attribute][0]
        except KeyError:
            logger.warning(
                "SAML2 response lacks a '%s' attestation", self._mxid_source_attribute,
            )
            raise SynapseError(
                400, "%s not in SAML2 response" % (self._mxid_source_attribute,)
            )

        # Use the configured mapper for this mxid_source
        base_mxid_localpart = self._mxid_mapper(mxid_source)

        # Append suffix integer if last call to this function failed to produce
        # a usable mxid
        localpart = base_mxid_localpart + (str(failures) if failures else "")

        # Retrieve the display name from the saml response
        # If displayname is None, the mxid_localpart will be used instead
        displayname = saml_response.ava.get("displayName", [None])[0]

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
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
    def get_saml_attributes(config: SamlConfig) -> Tuple[set, set]:
        """Returns the required attributes of a SAML

        Args:
            config: A SamlConfig object containing configuration params for this provider

        Returns:
            tuple[set,set]: The first set equates to the saml auth response
                attributes that are required for the module to function, whereas the
                second set consists of those attributes which can be used if
                available, but are not necessary
        """
        return {"uid", config.mxid_source_attribute}, {"displayName"}
