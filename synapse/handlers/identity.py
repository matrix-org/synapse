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
from signedjson.key import decode_verify_key_bytes
from signedjson.sign import verify_signed_json
from unpaddedbase64 import decode_base64

from twisted.internet import defer

from synapse.api.errors import (
    AuthError,
    CodeMessageException,
    Codes,
    HttpResponseException,
    SynapseError,
)
from synapse.util.hash import sha256_and_url_safe_base64

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

    @defer.inlineCallbacks
    def threepid_from_creds(self, creds):
        if "id_server" in creds:
            id_server = creds["id_server"]
        elif "idServer" in creds:
            id_server = creds["idServer"]
        else:
            raise SynapseError(400, "No id_server in creds")

        if "client_secret" in creds:
            client_secret = creds["client_secret"]
        elif "clientSecret" in creds:
            client_secret = creds["clientSecret"]
        else:
            raise SynapseError(400, "No client_secret in creds")

        if not self._should_trust_id_server(id_server):
            logger.warn(
                "%s is not a trusted ID server: rejecting 3pid " + "credentials",
                id_server,
            )
            return None

        try:
            data = yield self.http_client.get_json(
                "https://%s%s"
                % (id_server, "/_matrix/identity/api/v1/3pid/getValidated3pid"),
                {"sid": creds["sid"], "client_secret": client_secret},
            )
        except HttpResponseException as e:
            logger.info("getValidated3pid failed with Matrix error: %r", e)
            raise e.to_synapse_error()

        if "medium" in data:
            return data
        return None

    @defer.inlineCallbacks
    def bind_threepid(self, creds, mxid):
        logger.debug("binding threepid %r to %s", creds, mxid)
        data = None

        if "id_server" in creds:
            id_server = creds["id_server"]
        elif "idServer" in creds:
            id_server = creds["idServer"]
        else:
            raise SynapseError(400, "No id_server in creds")

        if "client_secret" in creds:
            client_secret = creds["client_secret"]
        elif "clientSecret" in creds:
            client_secret = creds["clientSecret"]
        else:
            raise SynapseError(400, "No client_secret in creds")

        try:
            data = yield self.http_client.post_json_get_json(
                "https://%s%s" % (id_server, "/_matrix/identity/api/v1/3pid/bind"),
                {"sid": creds["sid"], "client_secret": client_secret, "mxid": mxid},
            )
            logger.debug("bound threepid %r to %s", creds, mxid)

            # Remember where we bound the threepid
            yield self.store.add_user_bound_threepid(
                user_id=mxid,
                medium=data["medium"],
                address=data["address"],
                id_server=id_server,
            )
        except CodeMessageException as e:
            data = json.loads(e.msg)  # XXX WAT?
        return data

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
    def try_unbind_threepid_with_id_server(self, mxid, threepid, id_server):
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
            url_bytes="/_matrix/identity/api/v1/3pid/unbind".encode("ascii"),
            content=content,
            destination_is=id_server,
        )
        headers = {b"Authorization": auth_headers}

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

    @defer.inlineCallbacks
    def lookup_3pid(self, id_server, medium, address, id_access_token=None):
        """Looks up a 3pid in the passed identity server.

        Args:
            id_server (str): The server name (including protocol and port, if required)
                of the identity server to use.
            medium (str): The type of the third party identifier (e.g. "email").
            address (str): The third party identifier (e.g. "foo@example.com").
            id_access_token (str|None): The access token to authenticate to the identity
                server with

        Returns:
            str|None: the matrix ID of the 3pid, or None if it is not recognized.
        """
        # If an access token is present, add it to the query params of the hash_details request
        query_params = {}
        if id_access_token is not None:
            query_params["id_access_token"] = id_access_token

        # Check what hashing details are supported by this identity server
        use_v1 = False
        hash_details = None
        try:
            hash_details = yield self.http_client.get_json(
                "%s/_matrix/identity/v2/hash_details" % (id_server, ), query_params
            )
        except (HttpResponseException, ValueError) as e:
            # Catch HttpResponseExcept for a non-200 response code
            # Catch ValueError for non-JSON response body

            # Check if this identity server does not know about v2 lookups
            if e.code == 404:
                # This is an old identity server that does not yet support v2 lookups
                use_v1 = True
            else:
                logger.warning("Error when looking up hashing details: %s", e)
                return None

        if use_v1:
            return (yield self._lookup_3pid_v1(id_server, medium, address))

        return (
            yield self._lookup_3pid_v2(
                id_server, id_access_token, medium, address, hash_details
            )
        )

    @defer.inlineCallbacks
    def _lookup_3pid_v1(self, id_server, medium, address):
        """Looks up a 3pid in the passed identity server using v1 lookup.

        Args:
            id_server (str): The server name (including protocol and port, if required)
                of the identity server to use.
            medium (str): The type of the third party identifier (e.g. "email").
            address (str): The third party identifier (e.g. "foo@example.com").

        Returns:
            str: the matrix ID of the 3pid, or None if it is not recognized.
        """
        try:
            data = yield self.http_client.get_json(
                "%s/_matrix/identity/api/v1/lookup" % (id_server),
                {"medium": medium, "address": address},
            )

            if "mxid" in data:
                if "signatures" not in data:
                    raise AuthError(401, "No signatures on 3pid binding")
                yield self._verify_any_signature(data, id_server)
                return data["mxid"]

        except IOError as e:
            logger.warn("Error from identity server lookup: %s" % (e,))

        return None

    @defer.inlineCallbacks
    def _lookup_3pid_v2(
        self, id_server, id_access_token, medium, address, hash_details
    ):
        """Looks up a 3pid in the passed identity server using v2 lookup.

        Args:
            id_server (str): The server name (including protocol and port, if required)
                of the identity server to use.
            id_access_token (str): The access token to authenticate to the identity server with
            medium (str): The type of the third party identifier (e.g. "email").
            address (str): The third party identifier (e.g. "foo@example.com").
            hash_details (dict[str, str|list]): A dictionary containing hashing information
                provided by an identity server.

        Returns:
            Deferred[str|None]: the matrix ID of the 3pid, or None if it is not recognised.
        """
        # Extract information from hash_details
        supported_lookup_algorithms = hash_details["algorithms"]
        lookup_pepper = hash_details["lookup_pepper"]

        # Check if any of the supported lookup algorithms are present
        if LookupAlgorithm.SHA256 in supported_lookup_algorithms:
            # Perform a hashed lookup
            lookup_algorithm = LookupAlgorithm.SHA256

            # Hash address, medium and the pepper with sha256
            to_hash = "%s %s %s" % (address, medium, lookup_pepper)
            lookup_value = sha256_and_url_safe_base64(to_hash)

        elif LookupAlgorithm.NONE in supported_lookup_algorithms:
            # Perform a non-hashed lookup
            lookup_algorithm = LookupAlgorithm.NONE

            # Combine together plaintext address and medium
            lookup_value = "%s %s" % (address, medium)

        else:
            logger.warn(
                "None of the provided lookup algorithms of %s are supported: %s",
                id_server,
                hash_details["algorithms"],
            )
            raise SynapseError(
                400,
                "Provided identity server does not support any v2 lookup "
                "algorithms that this homeserver supports.",
            )

        try:
            lookup_results = yield self.http_client.post_json_get_json(
                "%s/_matrix/identity/v2/lookup" % id_server,
                {
                    "id_access_token": id_access_token,
                    "addresses": [lookup_value],
                    "algorithm": lookup_algorithm,
                    "pepper": lookup_pepper,
                },
            )
        except (HttpResponseException, ValueError) as e:
            # Catch HttpResponseExcept for a non-200 response code
            # Catch ValueError for non-JSON response body
            logger.warn("Error when performing a 3pid lookup: %s" % (e,))
            return None

        # Check for a mapping from what we looked up to an MXID
        if "mappings" not in lookup_results or not isinstance(
            lookup_results["mappings"], dict
        ):
            logger.debug("No results from 3pid lookup")
            return None

        # Return the MXID if it's available, or None otherwise
        mxid = lookup_results["mappings"].get(lookup_value)
        return mxid

    @defer.inlineCallbacks
    def _verify_any_signature(self, data, server_hostname):
        if server_hostname not in data["signatures"]:
            raise AuthError(401, "No signature from server %s" % (server_hostname,))
        for key_name, signature in data["signatures"][server_hostname].items():
            key_data = yield self.http_client.get_json(
                "%s/_matrix/identity/api/v1/pubkey/%s" % (server_hostname, key_name)
            )
            if "public_key" not in key_data:
                raise AuthError(
                    401, "No public key named %s from %s" % (key_name, server_hostname)
                )
            verify_signed_json(
                data,
                server_hostname,
                decode_verify_key_bytes(
                    key_name, decode_base64(key_data["public_key"])
                ),
            )
            return


class LookupAlgorithm:
    """
    Supported hashing algorithms when performing a 3PID lookup.

    SHA256 - Hashing an (address, medium, pepper) combo with sha256, then url-safe base64
        encoding
    NONE - Not performing any hashing. Simply sending an (address, medium) combo in plaintext
    """

    SHA256 = "sha256"
    NONE = "none"
