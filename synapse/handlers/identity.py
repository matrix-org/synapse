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
import urllib.parse
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from synapse.api.errors import (
    CodeMessageException,
    Codes,
    HttpResponseException,
    SynapseError,
)
from synapse.api.ratelimiting import Ratelimiter
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.http import RequestTimedOutError
from synapse.http.client import SimpleHttpClient
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict, Requester
from synapse.util import json_decoder
from synapse.util.hash import sha256_and_url_safe_base64
from synapse.util.stringutils import assert_valid_client_secret, random_string

from ._base import BaseHandler

logger = logging.getLogger(__name__)

id_server_scheme = "https://"


class IdentityHandler(BaseHandler):
    def __init__(self, hs):
        super().__init__(hs)

        # An HTTP client for contacting trusted URLs.
        self.http_client = SimpleHttpClient(hs)
        # An HTTP client for contacting identity servers specified by clients.
        self.blacklisting_http_client = SimpleHttpClient(
            hs, ip_blacklist=hs.config.federation_ip_range_blacklist
        )
        self.federation_http_client = hs.get_federation_http_client()
        self.hs = hs

        self._web_client_location = hs.config.invite_client_location

        # Ratelimiters for `/requestToken` endpoints.
        self._3pid_validation_ratelimiter_ip = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=hs.config.ratelimiting.rc_3pid_validation.per_second,
            burst_count=hs.config.ratelimiting.rc_3pid_validation.burst_count,
        )
        self._3pid_validation_ratelimiter_address = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=hs.config.ratelimiting.rc_3pid_validation.per_second,
            burst_count=hs.config.ratelimiting.rc_3pid_validation.burst_count,
        )

    def ratelimit_request_token_requests(
        self,
        request: SynapseRequest,
        medium: str,
        address: str,
    ):
        """Used to ratelimit requests to `/requestToken` by IP and address.

        Args:
            request: The associated request
            medium: The type of threepid, e.g. "msisdn" or "email"
            address: The actual threepid ID, e.g. the phone number or email address
        """

        self._3pid_validation_ratelimiter_ip.ratelimit((medium, request.getClientIP()))
        self._3pid_validation_ratelimiter_address.ratelimit((medium, address))

    async def threepid_from_creds(
        self, id_server: str, creds: Dict[str, str]
    ) -> Optional[JsonDict]:
        """
        Retrieve and validate a threepid identifier from a "credentials" dictionary against a
        given identity server

        Args:
            id_server: The identity server to validate 3PIDs against. Must be a
                complete URL including the protocol (http(s)://)
            creds: Dictionary containing the following keys:
                * client_secret|clientSecret: A unique secret str provided by the client
                * sid: The ID of the validation session

        Returns:
            A dictionary consisting of response params to the /getValidated3pid
            endpoint of the Identity Service API, or None if the threepid was not found
        """
        client_secret = creds.get("client_secret") or creds.get("clientSecret")
        if not client_secret:
            raise SynapseError(
                400, "Missing param client_secret in creds", errcode=Codes.MISSING_PARAM
            )
        assert_valid_client_secret(client_secret)

        session_id = creds.get("sid")
        if not session_id:
            raise SynapseError(
                400, "Missing param session_id in creds", errcode=Codes.MISSING_PARAM
            )

        query_params = {"sid": session_id, "client_secret": client_secret}

        url = id_server + "/_matrix/identity/api/v1/3pid/getValidated3pid"

        try:
            data = await self.http_client.get_json(url, query_params)
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")
        except HttpResponseException as e:
            logger.info(
                "%s returned %i for threepid validation for: %s",
                id_server,
                e.code,
                creds,
            )
            return None

        # Old versions of Sydent return a 200 http code even on a failed validation
        # check. Thus, in addition to the HttpResponseException check above (which
        # checks for non-200 errors), we need to make sure validation_session isn't
        # actually an error, identified by the absence of a "medium" key
        # See https://github.com/matrix-org/sydent/issues/215 for details
        if "medium" in data:
            return data

        logger.info("%s reported non-validated threepid: %s", id_server, creds)
        return None

    async def bind_threepid(
        self,
        client_secret: str,
        sid: str,
        mxid: str,
        id_server: str,
        id_access_token: Optional[str] = None,
        use_v2: bool = True,
    ) -> JsonDict:
        """Bind a 3PID to an identity server

        Args:
            client_secret: A unique secret provided by the client
            sid: The ID of the validation session
            mxid: The MXID to bind the 3PID to
            id_server: The domain of the identity server to query
            id_access_token: The access token to authenticate to the identity
                server with, if necessary. Required if use_v2 is true
            use_v2: Whether to use v2 Identity Service API endpoints. Defaults to True

        Returns:
            The response from the identity server
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
            headers["Authorization"] = create_id_access_token_header(id_access_token)  # type: ignore
        else:
            bind_url = "https://%s/_matrix/identity/api/v1/3pid/bind" % (id_server,)

        try:
            # Use the blacklisting http client as this call is only to identity servers
            # provided by a client
            data = await self.blacklisting_http_client.post_json_get_json(
                bind_url, bind_data, headers=headers
            )

            # Remember where we bound the threepid
            await self.store.add_user_bound_threepid(
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
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")
        except CodeMessageException as e:
            data = json_decoder.decode(e.msg)  # XXX WAT?
            return data

        logger.info("Got 404 when POSTing JSON %s, falling back to v1 URL", bind_url)
        res = await self.bind_threepid(
            client_secret, sid, mxid, id_server, id_access_token, use_v2=False
        )
        return res

    async def try_unbind_threepid(self, mxid: str, threepid: dict) -> bool:
        """Attempt to remove a 3PID from an identity server, or if one is not provided, all
        identity servers we're aware the binding is present on

        Args:
            mxid: Matrix user ID of binding to be removed
            threepid: Dict with medium & address of binding to be
                removed, and an optional id_server.

        Raises:
            SynapseError: If we failed to contact the identity server

        Returns:
            True on success, otherwise False if the identity
            server doesn't support unbinding (or no identity server found to
            contact).
        """
        if threepid.get("id_server"):
            id_servers = [threepid["id_server"]]
        else:
            id_servers = await self.store.get_id_servers_user_bound(
                user_id=mxid, medium=threepid["medium"], address=threepid["address"]
            )

        # We don't know where to unbind, so we don't have a choice but to return
        if not id_servers:
            return False

        changed = True
        for id_server in id_servers:
            changed &= await self.try_unbind_threepid_with_id_server(
                mxid, threepid, id_server
            )

        return changed

    async def try_unbind_threepid_with_id_server(
        self, mxid: str, threepid: dict, id_server: str
    ) -> bool:
        """Removes a binding from an identity server

        Args:
            mxid: Matrix user ID of binding to be removed
            threepid: Dict with medium & address of binding to be removed
            id_server: Identity server to unbind from

        Raises:
            SynapseError: If we failed to contact the identity server

        Returns:
            True on success, otherwise False if the identity
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
            method=b"POST",
            url_bytes=url_bytes,
            content=content,
            destination_is=id_server.encode("ascii"),
        )
        headers = {b"Authorization": auth_headers}

        try:
            # Use the blacklisting http client as this call is only to identity servers
            # provided by a client
            await self.blacklisting_http_client.post_json_get_json(
                url, content, headers
            )
            changed = True
        except HttpResponseException as e:
            changed = False
            if e.code in (400, 404, 501):
                # The remote server probably doesn't support unbinding (yet)
                logger.warning("Received %d response while unbinding threepid", e.code)
            else:
                logger.error("Failed to unbind threepid on identity server: %s", e)
                raise SynapseError(500, "Failed to contact identity server")
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")

        await self.store.remove_user_bound_threepid(
            user_id=mxid,
            medium=threepid["medium"],
            address=threepid["address"],
            id_server=id_server,
        )

        return changed

    async def send_threepid_validation(
        self,
        email_address: str,
        client_secret: str,
        send_attempt: int,
        send_email_func: Callable[[str, str, str, str], Awaitable],
        next_link: Optional[str] = None,
    ) -> str:
        """Send a threepid validation email for password reset or
        registration purposes

        Args:
            email_address: The user's email address
            client_secret: The provided client secret
            send_attempt: Which send attempt this is
            send_email_func: A function that takes an email address, token,
                             client_secret and session_id, sends an email
                             and returns an Awaitable.
            next_link: The URL to redirect the user to after validation

        Returns:
            The new session_id upon success

        Raises:
            SynapseError is an error occurred when sending the email
        """
        # Check that this email/client_secret/send_attempt combo is new or
        # greater than what we've seen previously
        session = await self.store.get_threepid_validation_session(
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

        if next_link:
            # Manipulate the next_link to add the sid, because the caller won't get
            # it until we send a response, by which time we've sent the mail.
            if "?" in next_link:
                next_link += "&"
            else:
                next_link += "?"
            next_link += "sid=" + urllib.parse.quote(session_id)

        # Generate a new validation token
        token = random_string(32)

        # Send the mail with the link containing the token, client_secret
        # and session_id
        try:
            await send_email_func(email_address, token, client_secret, session_id)
        except Exception:
            logger.exception(
                "Error sending threepid validation email to %s", email_address
            )
            raise SynapseError(500, "An error was encountered when sending the email")

        token_expires = (
            self.hs.get_clock().time_msec()
            + self.hs.config.email_validation_token_lifetime
        )

        await self.store.start_or_continue_validation_session(
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

    async def requestEmailToken(
        self,
        id_server: str,
        email: str,
        client_secret: str,
        send_attempt: int,
        next_link: Optional[str] = None,
    ) -> JsonDict:
        """
        Request an external server send an email on our behalf for the purposes of threepid
        validation.

        Args:
            id_server: The identity server to proxy to
            email: The email to send the message to
            client_secret: The unique client_secret sends by the user
            send_attempt: Which attempt this is
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
            logger.warning(
                'The config option "trust_identity_server_for_password_resets" '
                'has been replaced by "account_threepid_delegate". '
                "Please consult the sample config at docs/sample_config.yaml for "
                "details and update your config file."
            )

        try:
            data = await self.http_client.post_json_get_json(
                id_server + "/_matrix/identity/api/v1/validate/email/requestToken",
                params,
            )
            return data
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")

    async def requestMsisdnToken(
        self,
        id_server: str,
        country: str,
        phone_number: str,
        client_secret: str,
        send_attempt: int,
        next_link: Optional[str] = None,
    ) -> JsonDict:
        """
        Request an external server send an SMS message on our behalf for the purposes of
        threepid validation.
        Args:
            id_server: The identity server to proxy to
            country: The country code of the phone number
            phone_number: The number to send the message to
            client_secret: The unique client_secret sends by the user
            send_attempt: Which attempt this is
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
            logger.warning(
                'The config option "trust_identity_server_for_password_resets" '
                'has been replaced by "account_threepid_delegate". '
                "Please consult the sample config at docs/sample_config.yaml for "
                "details and update your config file."
            )

        try:
            data = await self.http_client.post_json_get_json(
                id_server + "/_matrix/identity/api/v1/validate/msisdn/requestToken",
                params,
            )
        except HttpResponseException as e:
            logger.info("Proxied requestToken failed: %r", e)
            raise e.to_synapse_error()
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")

        # It is already checked that public_baseurl is configured since this code
        # should only be used if account_threepid_delegate_msisdn is true.
        assert self.hs.config.public_baseurl

        # we need to tell the client to send the token back to us, since it doesn't
        # otherwise know where to send it, so add submit_url response parameter
        # (see also MSC2078)
        data["submit_url"] = (
            self.hs.config.public_baseurl
            + "_matrix/client/unstable/add_threepid/msisdn/submit_token"
        )
        return data

    async def validate_threepid_session(
        self, client_secret: str, sid: str
    ) -> Optional[JsonDict]:
        """Validates a threepid session with only the client secret and session ID
        Tries validating against any configured account_threepid_delegates as well as locally.

        Args:
            client_secret: A secret provided by the client
            sid: The ID of the session

        Returns:
            The json response if validation was successful, otherwise None
        """
        # XXX: We shouldn't need to keep wrapping and unwrapping this value
        threepid_creds = {"client_secret": client_secret, "sid": sid}

        # We don't actually know which medium this 3PID is. Thus we first assume it's email,
        # and if validation fails we try msisdn
        validation_session = None

        # Try to validate as email
        if self.hs.config.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
            # Ask our delegated email identity server
            validation_session = await self.threepid_from_creds(
                self.hs.config.account_threepid_delegate_email, threepid_creds
            )
        elif self.hs.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            # Get a validated session matching these details
            validation_session = await self.store.get_threepid_validation_session(
                "email", client_secret, sid=sid, validated=True
            )

        if validation_session:
            return validation_session

        # Try to validate as msisdn
        if self.hs.config.account_threepid_delegate_msisdn:
            # Ask our delegated msisdn identity server
            validation_session = await self.threepid_from_creds(
                self.hs.config.account_threepid_delegate_msisdn, threepid_creds
            )

        return validation_session

    async def proxy_msisdn_submit_token(
        self, id_server: str, client_secret: str, sid: str, token: str
    ) -> JsonDict:
        """Proxy a POST submitToken request to an identity server for verification purposes

        Args:
            id_server: The identity server URL to contact
            client_secret: Secret provided by the client
            sid: The ID of the session
            token: The verification token

        Raises:
            SynapseError: If we failed to contact the identity server

        Returns:
            The response dict from the identity server
        """
        body = {"client_secret": client_secret, "sid": sid, "token": token}

        try:
            return await self.http_client.post_json_get_json(
                id_server + "/_matrix/identity/api/v1/validate/msisdn/submitToken",
                body,
            )
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")
        except HttpResponseException as e:
            logger.warning("Error contacting msisdn account_threepid_delegate: %s", e)
            raise SynapseError(400, "Error contacting the identity server")

    async def lookup_3pid(
        self,
        id_server: str,
        medium: str,
        address: str,
        id_access_token: Optional[str] = None,
    ) -> Optional[str]:
        """Looks up a 3pid in the passed identity server.

        Args:
            id_server: The server name (including port, if required)
                of the identity server to use.
            medium: The type of the third party identifier (e.g. "email").
            address: The third party identifier (e.g. "foo@example.com").
            id_access_token: The access token to authenticate to the identity
                server with

        Returns:
            the matrix ID of the 3pid, or None if it is not recognized.
        """
        if id_access_token is not None:
            try:
                results = await self._lookup_3pid_v2(
                    id_server, id_access_token, medium, address
                )
                return results

            except Exception as e:
                # Catch HttpResponseExcept for a non-200 response code
                # Check if this identity server does not know about v2 lookups
                if isinstance(e, HttpResponseException) and e.code == 404:
                    # This is an old identity server that does not yet support v2 lookups
                    logger.warning(
                        "Attempted v2 lookup on v1 identity server %s. Falling "
                        "back to v1",
                        id_server,
                    )
                else:
                    logger.warning("Error when looking up hashing details: %s", e)
                    return None

        return await self._lookup_3pid_v1(id_server, medium, address)

    async def _lookup_3pid_v1(
        self, id_server: str, medium: str, address: str
    ) -> Optional[str]:
        """Looks up a 3pid in the passed identity server using v1 lookup.

        Args:
            id_server: The server name (including port, if required)
                of the identity server to use.
            medium: The type of the third party identifier (e.g. "email").
            address: The third party identifier (e.g. "foo@example.com").

        Returns:
            the matrix ID of the 3pid, or None if it is not recognized.
        """
        try:
            data = await self.blacklisting_http_client.get_json(
                "%s%s/_matrix/identity/api/v1/lookup" % (id_server_scheme, id_server),
                {"medium": medium, "address": address},
            )

            if "mxid" in data:
                # note: we used to verify the identity server's signature here, but no longer
                # require or validate it. See the following for context:
                # https://github.com/matrix-org/synapse/issues/5253#issuecomment-666246950
                return data["mxid"]
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")
        except IOError as e:
            logger.warning("Error from v1 identity server lookup: %s" % (e,))

        return None

    async def _lookup_3pid_v2(
        self, id_server: str, id_access_token: str, medium: str, address: str
    ) -> Optional[str]:
        """Looks up a 3pid in the passed identity server using v2 lookup.

        Args:
            id_server: The server name (including port, if required)
                of the identity server to use.
            id_access_token: The access token to authenticate to the identity server with
            medium: The type of the third party identifier (e.g. "email").
            address: The third party identifier (e.g. "foo@example.com").

        Returns:
            the matrix ID of the 3pid, or None if it is not recognised.
        """
        # Check what hashing details are supported by this identity server
        try:
            hash_details = await self.blacklisting_http_client.get_json(
                "%s%s/_matrix/identity/v2/hash_details" % (id_server_scheme, id_server),
                {"access_token": id_access_token},
            )
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")

        if not isinstance(hash_details, dict):
            logger.warning(
                "Got non-dict object when checking hash details of %s%s: %s",
                id_server_scheme,
                id_server,
                hash_details,
            )
            raise SynapseError(
                400,
                "Non-dict object from %s%s during v2 hash_details request: %s"
                % (id_server_scheme, id_server, hash_details),
            )

        # Extract information from hash_details
        supported_lookup_algorithms = hash_details.get("algorithms")
        lookup_pepper = hash_details.get("lookup_pepper")
        if (
            not supported_lookup_algorithms
            or not isinstance(supported_lookup_algorithms, list)
            or not lookup_pepper
            or not isinstance(lookup_pepper, str)
        ):
            raise SynapseError(
                400,
                "Invalid hash details received from identity server %s%s: %s"
                % (id_server_scheme, id_server, hash_details),
            )

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
            logger.warning(
                "None of the provided lookup algorithms of %s are supported: %s",
                id_server,
                supported_lookup_algorithms,
            )
            raise SynapseError(
                400,
                "Provided identity server does not support any v2 lookup "
                "algorithms that this homeserver supports.",
            )

        # Authenticate with identity server given the access token from the client
        headers = {"Authorization": create_id_access_token_header(id_access_token)}

        try:
            lookup_results = await self.blacklisting_http_client.post_json_get_json(
                "%s%s/_matrix/identity/v2/lookup" % (id_server_scheme, id_server),
                {
                    "addresses": [lookup_value],
                    "algorithm": lookup_algorithm,
                    "pepper": lookup_pepper,
                },
                headers=headers,
            )
        except RequestTimedOutError:
            raise SynapseError(500, "Timed out contacting identity server")
        except Exception as e:
            logger.warning("Error when performing a v2 3pid lookup: %s", e)
            raise SynapseError(
                500, "Unknown error occurred during identity server lookup"
            )

        # Check for a mapping from what we looked up to an MXID
        if "mappings" not in lookup_results or not isinstance(
            lookup_results["mappings"], dict
        ):
            logger.warning("No results from 3pid lookup")
            return None

        # Return the MXID if it's available, or None otherwise
        mxid = lookup_results["mappings"].get(lookup_value)
        return mxid

    async def ask_id_server_for_third_party_invite(
        self,
        requester: Requester,
        id_server: str,
        medium: str,
        address: str,
        room_id: str,
        inviter_user_id: str,
        room_alias: str,
        room_avatar_url: str,
        room_join_rules: str,
        room_name: str,
        inviter_display_name: str,
        inviter_avatar_url: str,
        id_access_token: Optional[str] = None,
    ) -> Tuple[str, List[Dict[str, str]], Dict[str, str], str]:
        """
        Asks an identity server for a third party invite.

        Args:
            requester
            id_server: hostname + optional port for the identity server.
            medium: The literal string "email".
            address: The third party address being invited.
            room_id: The ID of the room to which the user is invited.
            inviter_user_id: The user ID of the inviter.
            room_alias: An alias for the room, for cosmetic notifications.
            room_avatar_url: The URL of the room's avatar, for cosmetic
                notifications.
            room_join_rules: The join rules of the email (e.g. "public").
            room_name: The m.room.name of the room.
            inviter_display_name: The current display name of the
                inviter.
            inviter_avatar_url: The URL of the inviter's avatar.
            id_access_token (str|None): The access token to authenticate to the identity
                server with

        Returns:
            A tuple containing:
                token: The token which must be signed to prove authenticity.
                public_keys ([{"public_key": str, "key_validity_url": str}]):
                    public_key is a base64-encoded ed25519 public key.
                fallback_public_key: One element from public_keys.
                display_name: A user-friendly name to represent the invited user.
        """
        invite_config = {
            "medium": medium,
            "address": address,
            "room_id": room_id,
            "room_alias": room_alias,
            "room_avatar_url": room_avatar_url,
            "room_join_rules": room_join_rules,
            "room_name": room_name,
            "sender": inviter_user_id,
            "sender_display_name": inviter_display_name,
            "sender_avatar_url": inviter_avatar_url,
        }
        # If a custom web client location is available, include it in the request.
        if self._web_client_location:
            invite_config["org.matrix.web_client_location"] = self._web_client_location

        # Add the identity service access token to the JSON body and use the v2
        # Identity Service endpoints if id_access_token is present
        data = None
        base_url = "%s%s/_matrix/identity" % (id_server_scheme, id_server)

        if id_access_token:
            key_validity_url = "%s%s/_matrix/identity/v2/pubkey/isvalid" % (
                id_server_scheme,
                id_server,
            )

            # Attempt a v2 lookup
            url = base_url + "/v2/store-invite"
            try:
                data = await self.blacklisting_http_client.post_json_get_json(
                    url,
                    invite_config,
                    {"Authorization": create_id_access_token_header(id_access_token)},
                )
            except RequestTimedOutError:
                raise SynapseError(500, "Timed out contacting identity server")
            except HttpResponseException as e:
                if e.code != 404:
                    logger.info("Failed to POST %s with JSON: %s", url, e)
                    raise e

        if data is None:
            key_validity_url = "%s%s/_matrix/identity/api/v1/pubkey/isvalid" % (
                id_server_scheme,
                id_server,
            )
            url = base_url + "/api/v1/store-invite"

            try:
                data = await self.blacklisting_http_client.post_json_get_json(
                    url, invite_config
                )
            except RequestTimedOutError:
                raise SynapseError(500, "Timed out contacting identity server")
            except HttpResponseException as e:
                logger.warning(
                    "Error trying to call /store-invite on %s%s: %s",
                    id_server_scheme,
                    id_server,
                    e,
                )

            if data is None:
                # Some identity servers may only support application/x-www-form-urlencoded
                # types. This is especially true with old instances of Sydent, see
                # https://github.com/matrix-org/sydent/pull/170
                try:
                    data = await self.blacklisting_http_client.post_urlencoded_get_json(
                        url, invite_config
                    )
                except HttpResponseException as e:
                    logger.warning(
                        "Error calling /store-invite on %s%s with fallback "
                        "encoding: %s",
                        id_server_scheme,
                        id_server,
                        e,
                    )
                    raise e

        # TODO: Check for success
        token = data["token"]
        public_keys = data.get("public_keys", [])
        if "public_key" in data:
            fallback_public_key = {
                "public_key": data["public_key"],
                "key_validity_url": key_validity_url,
            }
        else:
            fallback_public_key = public_keys[0]

        if not public_keys:
            public_keys.append(fallback_public_key)
        display_name = data["display_name"]
        return token, public_keys, fallback_public_key, display_name


def create_id_access_token_header(id_access_token: str) -> List[str]:
    """Create an Authorization header for passing to SimpleHttpClient as the header value
    of an HTTP request.

    Args:
        id_access_token: An identity server access token.

    Returns:
        The ascii-encoded bearer token encased in a list.
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
