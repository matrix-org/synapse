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
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.util.stringutils import random_string

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class IdentityHandler(BaseHandler):
    def __init__(self, hs):
        super(IdentityHandler, self).__init__(hs)

        self.http_client = hs.get_simple_http_client()
        self.federation_http_client = hs.get_http_client()
        self.hs = hs
        self.identity_handler = hs.get_handlers().identity_handler

    @defer.inlineCallbacks
    def threepid_from_creds(self, id_server, creds):
        """
        Retrieve and validate a threepid identifier from a "credentials" dictionary against a
        given identity server

        Args:
            id_server (str): The identity server to validate 3PIDs against. Must be a
                complete URL including the protocol (http(s)://)

            creds (dict[str, str]): Dictionary containing the following keys:
                * client_secret|clientSecret: A unique secret str provided by the client
                * sid: The ID of the validation session

        Returns:
            Deferred[dict[str,str|int]|None]: A dictionary consisting of response params to
                the /getValidated3pid endpoint of the Identity Service API, or None if the
                threepid was not found
        """
        client_secret = creds.get("client_secret") or creds.get("clientSecret")
        if not client_secret:
            raise SynapseError(
                400, "Missing param client_secret in creds", errcode=Codes.MISSING_PARAM
            )
        session_id = creds.get("sid")
        if not session_id:
            raise SynapseError(
                400, "Missing param session_id in creds", errcode=Codes.MISSING_PARAM
            )

        query_params = {"sid": session_id, "client_secret": client_secret}

        url = id_server + "/_matrix/identity/api/v1/3pid/getValidated3pid"

        data = yield self.http_client.get_json(url, query_params)
        return data if "medium" in data else None

    @defer.inlineCallbacks
    def bind_threepid(
        self, client_secret, sid, mxid, id_server, id_access_token=None, use_v2=True
    ):
        """Bind a 3PID to an identity server

        Args:
            client_secret (str): A unique secret provided by the client

            sid (str): The ID of the validation session

            mxid (str): The MXID to bind the 3PID to

            id_server (str): The domain of the identity server to query

            id_access_token (str): The access token to authenticate to the identity
                server with, if necessary. Required if use_v2 is true

            use_v2 (bool): Whether to use v2 Identity Service API endpoints. Defaults to True

        Returns:
            Deferred[dict]: The response from the identity server
        """
        logger.debug("Proxying threepid bind request for %s to %s", mxid, id_server)

        # If an id_access_token is not supplied, force usage of v1
        if id_access_token is None:
            use_v2 = False

        # Decide which API endpoint URLs to use
        headers = {}
        bind_data = {"sid": sid, "client_secret": client_secret, "mxid": mxid}
        if use_v2:
            bind_url = "https://%s/_matrix/identity/v2/3pid/bind" % (id_server,)
            headers["Authorization"] = create_id_access_token_header(id_access_token)
        else:
            bind_url = "https://%s/_matrix/identity/api/v1/3pid/bind" % (id_server,)

        try:
            data = yield self.http_client.post_json_get_json(
                bind_url, bind_data, headers=headers
            )

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
        res = yield self.bind_threepid(
            client_secret, sid, mxid, id_server, id_access_token, use_v2=False
        )
        return res

    @defer.inlineCallbacks
    def try_unbind_threepid(self, mxid, threepid):
        """Attempt to remove a 3PID from an identity server, or if one is not provided, all
        identity servers we're aware the binding is present on

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
    def send_threepid_validation(
        self,
        email_address,
        client_secret,
        send_attempt,
        send_email_func,
        next_link=None,
    ):
        """Send a threepid validation email for password reset or
        registration purposes

        Args:
            email_address (str): The user's email address
            client_secret (str): The provided client secret
            send_attempt (int): Which send attempt this is
            send_email_func (func): A function that takes an email address, token,
                                    client_secret and session_id, sends an email
                                    and returns a Deferred.
            next_link (str|None): The URL to redirect the user to after validation

        Returns:
            The new session_id upon success

        Raises:
            SynapseError is an error occurred when sending the email
        """
        # Check that this email/client_secret/send_attempt combo is new or
        # greater than what we've seen previously
        session = yield self.store.get_threepid_validation_session(
            "email", client_secret, address=email_address, validated=False
        )

        # Check to see if a session already exists and that it is not yet
        # marked as validated
        if session and session.get("validated_at") is None:
            session_id = session["session_id"]
            last_send_attempt = session["last_send_attempt"]

            # Check that the send_attempt is higher than previous attempts
            if send_attempt <= last_send_attempt:
                # If not, just return a success without sending an email
                return session_id
        else:
            # An non-validated session does not exist yet.
            # Generate a session id
            session_id = random_string(16)

        # Generate a new validation token
        token = random_string(32)

        # Send the mail with the link containing the token, client_secret
        # and session_id
        try:
            yield send_email_func(email_address, token, client_secret, session_id)
        except Exception:
            logger.exception(
                "Error sending threepid validation email to %s", email_address
            )
            raise SynapseError(500, "An error was encountered when sending the email")

        token_expires = (
            self.hs.clock.time_msec() + self.hs.config.email_validation_token_lifetime
        )

        yield self.store.start_or_continue_validation_session(
            "email",
            email_address,
            session_id,
            client_secret,
            send_attempt,
            next_link,
            token,
            token_expires,
        )

        return session_id

    @defer.inlineCallbacks
    def requestEmailToken(
        self, id_server, email, client_secret, send_attempt, next_link=None
    ):
        """
        Request an external server send an email on our behalf for the purposes of threepid
        validation.

        Args:
            id_server (str): The identity server to proxy to
            email (str): The email to send the message to
            client_secret (str): The unique client_secret sends by the user
            send_attempt (int): Which attempt this is
            next_link: A link to redirect the user to once they submit the token

        Returns:
            The json response body from the server
        """
        params = {
            "email": email,
            "client_secret": client_secret,
            "send_attempt": send_attempt,
        }
        if next_link:
            params["next_link"] = next_link

        if self.hs.config.using_identity_server_from_trusted_list:
            # Warn that a deprecated config option is in use
            logger.warn(
                'The config option "trust_identity_server_for_password_resets" '
                'has been replaced by "account_threepid_delegate". '
                "Please consult the sample config at docs/sample_config.yaml for "
                "details and update your config file."
            )

        try:
            data = yield self.http_client.post_json_get_json(
                id_server + "/_matrix/identity/api/v1/validate/email/requestToken",
                params,
            )
            return data
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()

    @defer.inlineCallbacks
    def requestMsisdnToken(
        self,
        id_server,
        country,
        phone_number,
        client_secret,
        send_attempt,
        next_link=None,
    ):
        """
        Request an external server send an SMS message on our behalf for the purposes of
        threepid validation.
        Args:
            id_server (str): The identity server to proxy to
            country (str): The country code of the phone number
            phone_number (str): The number to send the message to
            client_secret (str): The unique client_secret sends by the user
            send_attempt (int): Which attempt this is
            next_link: A link to redirect the user to once they submit the token

        Returns:
            The json response body from the server
        """
        params = {
            "country": country,
            "phone_number": phone_number,
            "client_secret": client_secret,
            "send_attempt": send_attempt,
        }
        if next_link:
            params["next_link"] = next_link

        if self.hs.config.using_identity_server_from_trusted_list:
            # Warn that a deprecated config option is in use
            logger.warn(
                'The config option "trust_identity_server_for_password_resets" '
                'has been replaced by "account_threepid_delegate". '
                "Please consult the sample config at docs/sample_config.yaml for "
                "details and update your config file."
            )

        try:
            data = yield self.http_client.post_json_get_json(
                id_server + "/_matrix/identity/api/v1/validate/msisdn/requestToken",
                params,
            )
            return data
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()

    @defer.inlineCallbacks
    def validate_threepid_session(self, client_secret, sid):
        """Validates a threepid session with only the client secret and session ID
        Tries validating against any configured account_threepid_delegates as well as locally.

        Args:
            client_secret (str): A secret provided by the client

            sid (str): The ID of the session

        Returns:
            Dict[str, str|int] if validation was successful, otherwise None
        """
        # We don't actually know which medium this 3PID is. Thus we first assume it's email,
        # and if validation fails we try msisdn
        validation_session = None

        # XXX: We should need to keep wrapping and unwrapping this value
        threepid_creds = {"client_secret": client_secret, "sid": sid}

        # Try to validate as email
        if self.hs.config.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
            # Ask our delegated email identity server
            validation_session = yield self.identity_handler.threepid_from_creds(
                self.hs.config.account_threepid_delegate_email, threepid_creds
            )
        elif self.hs.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            # Get a validated session matching these details
            validation_session = yield self.store.get_threepid_validation_session(
                "email", client_secret, sid=sid, validated=True
            )

        if validation_session:
            return validation_session

        # Try to validate as msisdn
        if self.hs.config.account_threepid_delegate_msisdn:
            # Ask our delegated msisdn identity server
            validation_session = yield self.identity_handler.threepid_from_creds(
                self.hs.config.account_threepid_delegate_msisdn, threepid_creds
            )

        return validation_session


def create_id_access_token_header(id_access_token):
    """Create an Authorization header for passing to SimpleHttpClient as the header value
    of an HTTP request.

    Args:
        id_access_token (str): An identity server access token.

    Returns:
        list[str]: The ascii-encoded bearer token encased in a list.
    """
    # Prefix with Bearer
    bearer_token = "Bearer %s" % id_access_token

    # Encode headers to standard ascii
    bearer_token.encode("ascii")

    # Return as a list as that's how SimpleHttpClient takes header values
    return [bearer_token]


class LookupAlgorithm:
    """
    Supported hashing algorithms when performing a 3PID lookup.

    SHA256 - Hashing an (address, medium, pepper) combo with sha256, then url-safe base64
        encoding
    NONE - Not performing any hashing. Simply sending an (address, medium) combo in plaintext
    """

    SHA256 = "sha256"
    NONE = "none"
