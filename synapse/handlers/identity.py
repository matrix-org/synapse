# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
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

"""Utilities for interacting with Identity Servers"""

import logging

from canonicaljson import json

from twisted.internet import defer

from synapse.api.errors import (
    CodeMessageException,
    Codes,
    HttpResponseException,
    SynapseError,
)

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class IdentityHandler(BaseHandler):
    def __init__(self, hs):
        super(IdentityHandler, self).__init__(hs)

        self.http_client = hs.get_simple_http_client()
        self.federation_http_client = hs.get_http_client()

        self.trusted_id_servers = set(hs.config.trusted_third_party_id_servers)
        self.trust_any_id_server_just_for_testing_do_not_use = (
            hs.config.use_insecure_ssl_client_just_for_testing_do_not_use
        )

    def _should_trust_id_server(self, id_server):
        if id_server not in self.trusted_id_servers:
            if self.trust_any_id_server_just_for_testing_do_not_use:
                logger.warn(
                    "Trusting untrustworthy ID server %r even though it isn't"
                    " in the trusted id list for testing because"
                    " 'use_insecure_ssl_client_just_for_testing_do_not_use'"
                    " is set in the config",
                    id_server,
                )
            else:
                return False
        return True

    def _extract_items_from_creds_dict(self, creds):
        """
        Retrieve entries from a "credentials" dictionary

        Args:
            creds (dict[str, str]): Dictionary of credentials that contain the following keys:
                * client_secret|clientSecret: A unique secret str provided by the client
                * id_server|idServer: the domain of the identity server to query
                * id_access_token: The access token to authenticate to the identity
                    server with.

        Returns:
            tuple(str, str, str|None): A tuple containing the client_secret, the id_server,
                and the id_access_token value if available.
        """
        client_secret = creds.get("client_secret") or creds.get("clientSecret")
        if not client_secret:
            raise SynapseError(
                400, "No client_secret in creds", errcode=Codes.MISSING_PARAM
            )

        id_server = creds.get("id_server") or creds.get("idServer")
        if not id_server:
            raise SynapseError(
                400, "No id_server in creds", errcode=Codes.MISSING_PARAM
            )

        id_access_token = creds.get("id_access_token")
        return client_secret, id_server, id_access_token

    @defer.inlineCallbacks
    def threepid_from_creds(self, creds, use_v2=True):
        """
        Retrieve and validate a threepid identitier from a "credentials" dictionary

        Args:
            creds (dict[str, str]): Dictionary of credentials that contain the following keys:
                * client_secret|clientSecret: A unique secret str provided by the client
                * id_server|idServer: the domain of the identity server to query
                * id_access_token: The access token to authenticate to the identity
                    server with. Required if use_v2 is true
            use_v2 (bool): Whether to use v2 Identity Service API endpoints

        Returns:
            Deferred[dict[str,str|int]|None]: A dictionary consisting of response params to
                the /getValidated3pid endpoint of the Identity Service API, or None if the
                threepid was not found
        """
        client_secret, id_server, id_access_token = self._extract_items_from_creds_dict(
            creds
        )

        # If an id_access_token is not supplied, force usage of v1
        if id_access_token is None:
            use_v2 = False

        query_params = {"sid": creds["sid"], "client_secret": client_secret}

        # Decide which API endpoint URLs and query parameters to use
        if use_v2:
            url = "https://%s%s" % (
                id_server,
                "/_matrix/identity/v2/3pid/getValidated3pid",
            )
            query_params["id_access_token"] = id_access_token
        else:
            url = "https://%s%s" % (
                id_server,
                "/_matrix/identity/api/v1/3pid/getValidated3pid",
            )

        if not self._should_trust_id_server(id_server):
            logger.warn(
                "%s is not a trusted ID server: rejecting 3pid " + "credentials",
                id_server,
            )
            return None

        try:
            data = yield self.http_client.get_json(url, query_params)
            return data if "medium" in data else None
        except HttpResponseException as e:
            if e.code != 404 or not use_v2:
                # Generic failure
                logger.info("getValidated3pid failed with Matrix error: %r", e)
                raise e.to_synapse_error()

        # This identity server is too old to understand Identity Service API v2
        # Attempt v1 endpoint
        logger.info("Got 404 when POSTing JSON %s, falling back to v1 URL", url)
        return (yield self.threepid_from_creds(creds, use_v2=False))

    @defer.inlineCallbacks
    def bind_threepid(self, creds, mxid, use_v2=True):
        """Bind a 3PID to an identity server

        Args:
            creds (dict[str, str]): Dictionary of credentials that contain the following keys:
                * client_secret|clientSecret: A unique secret str provided by the client
                * id_server|idServer: the domain of the identity server to query
                * id_access_token: The access token to authenticate to the identity
                    server with. Required if use_v2 is true
            mxid (str): The MXID to bind the 3PID to
            use_v2 (bool): Whether to use v2 Identity Service API endpoints

        Returns:
            Deferred[dict]: The response from the identity server
        """
        logger.debug("binding threepid %r to %s", creds, mxid)

        client_secret, id_server, id_access_token = self._extract_items_from_creds_dict(
            creds
        )

        # If an id_access_token is not supplied, force usage of v1
        if id_access_token is None:
            use_v2 = False

        # Decide which API endpoint URLs to use
        bind_data = {"sid": creds["sid"], "client_secret": client_secret, "mxid": mxid}
        if use_v2:
            bind_url = "https://%s/_matrix/identity/v2/3pid/bind" % (id_server,)
            bind_data["id_access_token"] = id_access_token
        else:
            bind_url = "https://%s/_matrix/identity/api/v1/3pid/bind" % (id_server,)

        try:
            data = yield self.http_client.post_json_get_json(bind_url, bind_data)
            logger.debug("bound threepid %r to %s", creds, mxid)

            # Remember where we bound the threepid
            yield self.store.add_user_bound_threepid(
                user_id=mxid,
                medium=data["medium"],
                address=data["address"],
                id_server=id_server,
            )

            return data
        except HttpResponseException as e:
            if e.code != 404 or not use_v2:
                logger.error("3PID bind failed with Matrix error: %r", e)
                raise e.to_synapse_error()
        except CodeMessageException as e:
            data = json.loads(e.msg)  # XXX WAT?
            return data

        logger.info("Got 404 when POSTing JSON %s, falling back to v1 URL", bind_url)
        return (yield self.bind_threepid(creds, mxid, use_v2=False))

    @defer.inlineCallbacks
    def try_unbind_threepid(self, mxid, threepid):
        """Removes a binding from an identity server

        Args:
            mxid (str): Matrix user ID of binding to be removed
            threepid (dict): Dict with medium & address of binding to be
                removed, and an optional id_server.

        Raises:
            SynapseError: If we failed to contact the identity server

        Returns:
            Deferred[bool]: True on success, otherwise False if the identity
            server doesn't support unbinding (or no identity server found to
            contact).
        """
        if threepid.get("id_server"):
            id_servers = [threepid["id_server"]]
        else:
            id_servers = yield self.store.get_id_servers_user_bound(
                user_id=mxid, medium=threepid["medium"], address=threepid["address"]
            )

        # We don't know where to unbind, so we don't have a choice but to return
        if not id_servers:
            return False

        changed = True
        for id_server in id_servers:
            changed &= yield self.try_unbind_threepid_with_id_server(
                mxid, threepid, id_server
            )

        return changed

    @defer.inlineCallbacks
    def try_unbind_threepid_with_id_server(
        self, mxid, threepid, id_server
    ):
        """Removes a binding from an identity server

        Args:
            mxid (str): Matrix user ID of binding to be removed
            threepid (dict): Dict with medium & address of binding to be removed
            id_server (str): Identity server to unbind from

        Raises:
            SynapseError: If we failed to contact the identity server

        Returns:
            Deferred[bool]: True on success, otherwise False if the identity
            server doesn't support unbinding
        """
        url = "https://%s/_matrix/identity/api/v1/3pid/unbind" % (id_server,)
        url_bytes = "/_matrix/identity/api/v1/3pid/unbind".encode("ascii")

        content = {
            "mxid": mxid,
            "threepid": {"medium": threepid["medium"], "address": threepid["address"]},
        }

        # we abuse the federation http client to sign the request, but we have to send it
        # using the normal http client since we don't want the SRV lookup and want normal
        # 'browser-like' HTTPS.
        auth_headers = self.federation_http_client.build_auth_headers(
            destination=None,
            method="POST",
            url_bytes=url_bytes,
            content=content,
            destination_is=id_server,
        )
        headers = {b"Authorization": auth_headers}

        v1_fallback = False
        try:
            yield self.http_client.post_json_get_json(url, content, headers)
            changed = True
        except HttpResponseException as e:
            changed = False
            if e.code in (400, 404, 501):
                # The remote server probably doesn't support unbinding (yet)
                logger.warn("Received %d response while unbinding threepid", e.code)
            else:
                logger.error("Failed to unbind threepid on identity server: %s", e)
                raise SynapseError(502, "Failed to contact identity server")

        yield self.store.remove_user_bound_threepid(
            user_id=mxid,
            medium=threepid["medium"],
            address=threepid["address"],
            id_server=id_server,
        )

        return changed

    @defer.inlineCallbacks
    def requestEmailToken(
        self, id_server, email, client_secret, send_attempt, next_link=None
    ):
        if not self._should_trust_id_server(id_server):
            raise SynapseError(
                400, "Untrusted ID server '%s'" % id_server, Codes.SERVER_NOT_TRUSTED
            )

        params = {
            "email": email,
            "client_secret": client_secret,
            "send_attempt": send_attempt,
        }

        if next_link:
            params.update({"next_link": next_link})

        try:
            data = yield self.http_client.post_json_get_json(
                "https://%s%s"
                % (id_server, "/_matrix/identity/api/v1/validate/email/requestToken"),
                params,
            )
            return data
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()

    @defer.inlineCallbacks
    def requestMsisdnToken(
        self, id_server, country, phone_number, client_secret, send_attempt, **kwargs
    ):
        if not self._should_trust_id_server(id_server):
            raise SynapseError(
                400, "Untrusted ID server '%s'" % id_server, Codes.SERVER_NOT_TRUSTED
            )

        params = {
            "country": country,
            "phone_number": phone_number,
            "client_secret": client_secret,
            "send_attempt": send_attempt,
        }
        params.update(kwargs)

        try:
            data = yield self.http_client.post_json_get_json(
                "https://%s%s"
                % (id_server, "/_matrix/identity/api/v1/validate/msisdn/requestToken"),
                params,
            )
            return data
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()
