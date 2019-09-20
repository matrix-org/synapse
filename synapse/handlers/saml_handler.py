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

        try:
            mxid_source = saml2_auth.ava[self._mxid_source_attribute][0]
        except KeyError:
            logger.warning(
                "SAML2 response lacks a '%s' attestation", self._mxid_source_attribute
            )
            raise SynapseError(
                400, "%s not in SAML2 response" % (self._mxid_source_attribute,)
            )

        self._outstanding_requests_dict.pop(saml2_auth.in_response_to, None)

        displayName = saml2_auth.ava.get("displayName", [None])[0]

        # mozilla-specific hack: truncate at @
        if displayName:
            pos = displayName.find("@")
            if pos >= 0:
                displayName = displayName[:pos]

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

            # figure out a new mxid for this user
            base_mxid_localpart = self._mxid_mapper(mxid_source)

            suffix = 0
            while True:
                localpart = base_mxid_localpart + (str(suffix) if suffix else "")
                if not await self._datastore.get_users_by_id_case_insensitive(
                    UserID(localpart, self._hostname).to_string()
                ):
                    break
                suffix += 1
            logger.info("Allocating mxid for new user with localpart %s", localpart)

            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart, default_display_name=displayName
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
