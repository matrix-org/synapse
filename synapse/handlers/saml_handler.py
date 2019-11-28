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
import saml2.response
from saml2.client import Saml2Client

from synapse.api.errors import SynapseError
from synapse.http.servlet import parse_string
from synapse.rest.client.v1.login import SSOAuthHandler
from synapse.types import UserID, map_username_to_mxid_localpart
from synapse.util.async_helpers import Linearizer

logger = logging.getLogger(__name__)


class SamlHandler:
    def __init__(self, hs):
        self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._sso_auth_handler = SSOAuthHandler(hs)
        self._registration_handler = hs.get_registration_handler()

        self._clock = hs.get_clock()
        self._datastore = hs.get_datastore()
        self._hostname = hs.hostname
        self._saml2_session_lifetime = hs.config.saml2_session_lifetime
        self._mxid_source_attribute = hs.config.saml2_mxid_source_attribute
        self._grandfathered_mxid_source_attribute = (
            hs.config.saml2_grandfathered_mxid_source_attribute
        )
        self._mxid_mapper = hs.config.saml2_mxid_mapper

        # plugin to do custom mapping from saml response to mxid
        self._mapping_provider = hs.config.saml2_mapping_provider

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

        user_id = await self._map_saml_response_to_user(resp_bytes)
        self._sso_auth_handler.complete_sso_login(user_id, request, relay_state)

    async def _map_saml_response_to_user(self, resp_bytes):
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

        logger.info("SAML2 response: %s", saml2_auth.origxml)
        logger.info("SAML2 mapped attributes: %s", saml2_auth.ava)

        try:
            remote_user_id = saml2_auth.ava["uid"][0]
        except KeyError:
            logger.warning("SAML2 response lacks a 'uid' attestation")
            raise SynapseError(400, "uid not in SAML2 response")

        self._outstanding_requests_dict.pop(saml2_auth.in_response_to, None)

        # Map saml response to user attributes using the configured mapping provider
        for i in range(1000):
            try:
                attribute_dict = self._mapping_provider.saml_response_to_user_attributes(
                    saml2_auth, i
                )
            except Exception:
                logging.exception("Error in SAML mapping provider plugin")
                raise SynapseError(500, "Error parsing SAML2 response")

            localpart = attribute_dict.get("mxid_localpart")
            if not localpart:
                logger.error(
                    "SAML mapping provider plugin did not return a mxid_localpart object"
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


@attr.s
class Saml2SessionData:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time = attr.ib()


class DefaultSamlMappingProvider(object):
    __version__ = "0.0.1"

    def __init__(self):
        self._mxid_mapper = None
        self._mxid_source_attribute = None

    def saml_response_to_user_attributes(
        self, saml_response: saml2.response.AuthnResponse, failures: int = 0,
    ) -> dict:
        """Maps some text from a SAML response to attributes of a new user

        Args:
            saml_response: A SAML auth response object

            failures: How many times a call to this function with this
                saml_response has resulted in a failure

        Returns:
            dict: A dict containing new user attributes. Possible keys:
                * mxid_localpart (str): Required. The localpart of the user's mxid
                * displayname (str): The displayname of the user
        """
        try:
            mxid_source = saml_response.ava[self._mxid_source_attribute][0]
        except KeyError:
            logger.warning(
                "SAML2 response lacks a '%s' attestation", self._mxid_source_attribute
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
        displayname = saml_response.ava.get("displayName", [None])[0]

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
        }

    def parse_config(self, config):
        """Parse the dict provided by the homeserver config"""
        self._mxid_source_attribute = config.get("mxid_source_attribute", "uid")
        self._mxid_source_attribute = config.get("mxid_mapping", "hexencode")
