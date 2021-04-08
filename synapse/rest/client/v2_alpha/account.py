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
import logging
import random
from http import HTTPStatus
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from synapse.api.constants import LoginType
from synapse.api.errors import (
    Codes,
    InteractiveAuthIncompleteError,
    SynapseError,
    ThreepidValidationError,
)
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.handlers.ui_auth import UIAuthSessionDataConstants
from synapse.http.server import finish_request, respond_with_html
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)
from synapse.metrics import threepid_send_requests
from synapse.push.mailer import Mailer
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.stringutils import assert_valid_client_secret, random_string
from synapse.util.threepids import canonicalise_email, check_3pid_allowed

from ._base import client_patterns, interactive_auth_handler

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class EmailPasswordRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password/email/requestToken$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.datastore = hs.get_datastore()
        self.config = hs.config
        self.identity_handler = hs.get_identity_handler()

        if self.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            self.mailer = Mailer(
                hs=self.hs,
                app_name=self.config.email_app_name,
                template_html=self.config.email_password_reset_template_html,
                template_text=self.config.email_password_reset_template_text,
            )

    async def on_POST(self, request):
        if self.config.threepid_behaviour_email == ThreepidBehaviour.OFF:
            if self.config.local_threepid_handling_disabled_due_to_email_config:
                logger.warning(
                    "User password resets have been disabled due to lack of email config"
                )
            raise SynapseError(
                400, "Email-based password resets have been disabled on this server"
            )

        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["client_secret", "email", "send_attempt"])

        # Extract params from body
        client_secret = body["client_secret"]
        assert_valid_client_secret(client_secret)

        # Canonicalise the email address. The addresses are all stored canonicalised
        # in the database. This allows the user to reset his password without having to
        # know the exact spelling (eg. upper and lower case) of address in the database.
        # Stored in the database "foo@bar.com"
        # User requests with "FOO@bar.com" would raise a Not Found error
        try:
            email = canonicalise_email(body["email"])
        except ValueError as e:
            raise SynapseError(400, str(e))
        send_attempt = body["send_attempt"]
        next_link = body.get("next_link")  # Optional param

        if next_link:
            # Raise if the provided next_link value isn't valid
            assert_valid_next_link(self.hs, next_link)

        await self.identity_handler.ratelimit_request_token_requests(
            request, "email", email
        )

        # The email will be sent to the stored address.
        # This avoids a potential account hijack by requesting a password reset to
        # an email address which is controlled by the attacker but which, after
        # canonicalisation, matches the one in our database.
        existing_user_id = await self.hs.get_datastore().get_user_id_by_threepid(
            "email", email
        )

        if existing_user_id is None:
            if self.config.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "Email not found", Codes.THREEPID_NOT_FOUND)

        if self.config.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
            assert self.hs.config.account_threepid_delegate_email

            # Have the configured identity server handle the request
            ret = await self.identity_handler.requestEmailToken(
                self.hs.config.account_threepid_delegate_email,
                email,
                client_secret,
                send_attempt,
                next_link,
            )
        else:
            # Send password reset emails from Synapse
            sid = await self.identity_handler.send_threepid_validation(
                email,
                client_secret,
                send_attempt,
                self.mailer.send_password_reset_mail,
                next_link,
            )

            # Wrap the session id in a JSON object
            ret = {"sid": sid}

        threepid_send_requests.labels(type="email", reason="password_reset").observe(
            send_attempt
        )

        return 200, ret


class PasswordRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastore()
        self.password_policy_handler = hs.get_password_policy_handler()
        self._set_password_handler = hs.get_set_password_handler()

    @interactive_auth_handler
    async def on_POST(self, request):
        body = parse_json_object_from_request(request)

        # we do basic sanity checks here because the auth layer will store these
        # in sessions. Pull out the new password provided to us.
        new_password = body.pop("new_password", None)
        if new_password is not None:
            if not isinstance(new_password, str) or len(new_password) > 512:
                raise SynapseError(400, "Invalid password")
            self.password_policy_handler.validate_password(new_password)

        # there are two possibilities here. Either the user does not have an
        # access token, and needs to do a password reset; or they have one and
        # need to validate their identity.
        #
        # In the first case, we offer a couple of means of identifying
        # themselves (email and msisdn, though it's unclear if msisdn actually
        # works).
        #
        # In the second case, we require a password to confirm their identity.

        if self.auth.has_access_token(request):
            requester = await self.auth.get_user_by_req(request)
            try:
                params, session_id = await self.auth_handler.validate_user_via_ui_auth(
                    requester,
                    request,
                    body,
                    "modify your account password",
                )
            except InteractiveAuthIncompleteError as e:
                # The user needs to provide more steps to complete auth, but
                # they're not required to provide the password again.
                #
                # If a password is available now, hash the provided password and
                # store it for later.
                if new_password:
                    password_hash = await self.auth_handler.hash(new_password)
                    await self.auth_handler.set_session_data(
                        e.session_id,
                        UIAuthSessionDataConstants.PASSWORD_HASH,
                        password_hash,
                    )
                raise
            user_id = requester.user.to_string()
        else:
            requester = None
            try:
                result, params, session_id = await self.auth_handler.check_ui_auth(
                    [[LoginType.EMAIL_IDENTITY]],
                    request,
                    body,
                    "modify your account password",
                )
            except InteractiveAuthIncompleteError as e:
                # The user needs to provide more steps to complete auth, but
                # they're not required to provide the password again.
                #
                # If a password is available now, hash the provided password and
                # store it for later.
                if new_password:
                    password_hash = await self.auth_handler.hash(new_password)
                    await self.auth_handler.set_session_data(
                        e.session_id,
                        UIAuthSessionDataConstants.PASSWORD_HASH,
                        password_hash,
                    )
                raise

            if LoginType.EMAIL_IDENTITY in result:
                threepid = result[LoginType.EMAIL_IDENTITY]
                if "medium" not in threepid or "address" not in threepid:
                    raise SynapseError(500, "Malformed threepid")
                if threepid["medium"] == "email":
                    # For emails, canonicalise the address.
                    # We store all email addresses canonicalised in the DB.
                    # (See add_threepid in synapse/handlers/auth.py)
                    try:
                        threepid["address"] = canonicalise_email(threepid["address"])
                    except ValueError as e:
                        raise SynapseError(400, str(e))
                # if using email, we must know about the email they're authing with!
                threepid_user_id = await self.datastore.get_user_id_by_threepid(
                    threepid["medium"], threepid["address"]
                )
                if not threepid_user_id:
                    raise SynapseError(404, "Email address not found", Codes.NOT_FOUND)
                user_id = threepid_user_id
            else:
                logger.error("Auth succeeded but no known type! %r", result.keys())
                raise SynapseError(500, "", Codes.UNKNOWN)

        # If we have a password in this request, prefer it. Otherwise, use the
        # password hash from an earlier request.
        if new_password:
            password_hash = await self.auth_handler.hash(new_password)
        elif session_id is not None:
            password_hash = await self.auth_handler.get_session_data(
                session_id, UIAuthSessionDataConstants.PASSWORD_HASH, None
            )
        else:
            # UI validation was skipped, but the request did not include a new
            # password.
            password_hash = None
        if not password_hash:
            raise SynapseError(400, "Missing params: password", Codes.MISSING_PARAM)

        logout_devices = params.get("logout_devices", True)

        await self._set_password_handler.set_password(
            user_id, password_hash, logout_devices, requester
        )

        return 200, {}


class DeactivateAccountRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/deactivate$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self._deactivate_account_handler = hs.get_deactivate_account_handler()

    @interactive_auth_handler
    async def on_POST(self, request):
        body = parse_json_object_from_request(request)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        requester = await self.auth.get_user_by_req(request)

        # allow ASes to deactivate their own users
        if requester.app_service:
            await self._deactivate_account_handler.deactivate_account(
                requester.user.to_string(), erase, requester
            )
            return 200, {}

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body,
            "deactivate your account",
        )
        result = await self._deactivate_account_handler.deactivate_account(
            requester.user.to_string(),
            erase,
            requester,
            id_server=body.get("id_server"),
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        return 200, {"id_server_unbind_result": id_server_unbind_result}


class EmailThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/email/requestToken$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.config = hs.config
        self.identity_handler = hs.get_identity_handler()
        self.store = self.hs.get_datastore()

        if self.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            self.mailer = Mailer(
                hs=self.hs,
                app_name=self.config.email_app_name,
                template_html=self.config.email_add_threepid_template_html,
                template_text=self.config.email_add_threepid_template_text,
            )

    async def on_POST(self, request):
        if self.config.threepid_behaviour_email == ThreepidBehaviour.OFF:
            if self.config.local_threepid_handling_disabled_due_to_email_config:
                logger.warning(
                    "Adding emails have been disabled due to lack of an email config"
                )
            raise SynapseError(
                400, "Adding an email to your account is disabled on this server"
            )

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["client_secret", "email", "send_attempt"])
        client_secret = body["client_secret"]
        assert_valid_client_secret(client_secret)

        # Canonicalise the email address. The addresses are all stored canonicalised
        # in the database.
        # This ensures that the validation email is sent to the canonicalised address
        # as it will later be entered into the database.
        # Otherwise the email will be sent to "FOO@bar.com" and stored as
        # "foo@bar.com" in database.
        try:
            email = canonicalise_email(body["email"])
        except ValueError as e:
            raise SynapseError(400, str(e))
        send_attempt = body["send_attempt"]
        next_link = body.get("next_link")  # Optional param

        if not check_3pid_allowed(self.hs, "email", email):
            raise SynapseError(
                403,
                "Your email domain is not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        await self.identity_handler.ratelimit_request_token_requests(
            request, "email", email
        )

        if next_link:
            # Raise if the provided next_link value isn't valid
            assert_valid_next_link(self.hs, next_link)

        existing_user_id = await self.store.get_user_id_by_threepid("email", email)

        if existing_user_id is not None:
            if self.config.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "Email is already in use", Codes.THREEPID_IN_USE)

        if self.config.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
            assert self.hs.config.account_threepid_delegate_email

            # Have the configured identity server handle the request
            ret = await self.identity_handler.requestEmailToken(
                self.hs.config.account_threepid_delegate_email,
                email,
                client_secret,
                send_attempt,
                next_link,
            )
        else:
            # Send threepid validation emails from Synapse
            sid = await self.identity_handler.send_threepid_validation(
                email,
                client_secret,
                send_attempt,
                self.mailer.send_add_threepid_mail,
                next_link,
            )

            # Wrap the session id in a JSON object
            ret = {"sid": sid}

        threepid_send_requests.labels(type="email", reason="add_threepid").observe(
            send_attempt
        )

        return 200, ret


class MsisdnThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/msisdn/requestToken$")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        super().__init__()
        self.store = self.hs.get_datastore()
        self.identity_handler = hs.get_identity_handler()

    async def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(
            body, ["client_secret", "country", "phone_number", "send_attempt"]
        )
        client_secret = body["client_secret"]
        assert_valid_client_secret(client_secret)

        country = body["country"]
        phone_number = body["phone_number"]
        send_attempt = body["send_attempt"]
        next_link = body.get("next_link")  # Optional param

        msisdn = phone_number_to_msisdn(country, phone_number)

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Account phone numbers are not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        await self.identity_handler.ratelimit_request_token_requests(
            request, "msisdn", msisdn
        )

        if next_link:
            # Raise if the provided next_link value isn't valid
            assert_valid_next_link(self.hs, next_link)

        existing_user_id = await self.store.get_user_id_by_threepid("msisdn", msisdn)

        if existing_user_id is not None:
            if self.hs.config.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "MSISDN is already in use", Codes.THREEPID_IN_USE)

        if not self.hs.config.account_threepid_delegate_msisdn:
            logger.warning(
                "No upstream msisdn account_threepid_delegate configured on the server to "
                "handle this request"
            )
            raise SynapseError(
                400,
                "Adding phone numbers to user account is not supported by this homeserver",
            )

        ret = await self.identity_handler.requestMsisdnToken(
            self.hs.config.account_threepid_delegate_msisdn,
            country,
            phone_number,
            client_secret,
            send_attempt,
            next_link,
        )

        threepid_send_requests.labels(type="msisdn", reason="add_threepid").observe(
            send_attempt
        )

        return 200, ret


class AddThreepidEmailSubmitTokenServlet(RestServlet):
    """Handles 3PID validation token submission for adding an email to a user's account"""

    PATTERNS = client_patterns(
        "/add_threepid/email/submit_token$", releases=(), unstable=True
    )

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.config = hs.config
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        if self.config.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            self._failure_email_template = (
                self.config.email_add_threepid_template_failure_html
            )

    async def on_GET(self, request):
        if self.config.threepid_behaviour_email == ThreepidBehaviour.OFF:
            if self.config.local_threepid_handling_disabled_due_to_email_config:
                logger.warning(
                    "Adding emails have been disabled due to lack of an email config"
                )
            raise SynapseError(
                400, "Adding an email to your account is disabled on this server"
            )
        elif self.config.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
            raise SynapseError(
                400,
                "This homeserver is not validating threepids. Use an identity server "
                "instead.",
            )

        sid = parse_string(request, "sid", required=True)
        token = parse_string(request, "token", required=True)
        client_secret = parse_string(request, "client_secret", required=True)
        assert_valid_client_secret(client_secret)

        # Attempt to validate a 3PID session
        try:
            # Mark the session as valid
            next_link = await self.store.validate_threepid_session(
                sid, client_secret, token, self.clock.time_msec()
            )

            # Perform a 302 redirect if next_link is set
            if next_link:
                request.setResponseCode(302)
                request.setHeader("Location", next_link)
                finish_request(request)
                return None

            # Otherwise show the success template
            html = self.config.email_add_threepid_template_success_html_content
            status_code = 200
        except ThreepidValidationError as e:
            status_code = e.code

            # Show a failure page with a reason
            template_vars = {"failure_reason": e.msg}
            html = self._failure_email_template.render(**template_vars)

        respond_with_html(request, status_code, html)


class AddThreepidMsisdnSubmitTokenServlet(RestServlet):
    """Handles 3PID validation token submission for adding a phone number to a user's
    account
    """

    PATTERNS = client_patterns(
        "/add_threepid/msisdn/submit_token$", releases=(), unstable=True
    )

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.config = hs.config
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.identity_handler = hs.get_identity_handler()

    async def on_POST(self, request):
        if not self.config.account_threepid_delegate_msisdn:
            raise SynapseError(
                400,
                "This homeserver is not validating phone numbers. Use an identity server "
                "instead.",
            )

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["client_secret", "sid", "token"])
        assert_valid_client_secret(body["client_secret"])

        # Proxy submit_token request to msisdn threepid delegate
        response = await self.identity_handler.proxy_msisdn_submit_token(
            self.config.account_threepid_delegate_msisdn,
            body["client_secret"],
            body["sid"],
            body["token"],
        )
        return 200, response


class ThreepidRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastore()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request)

        threepids = await self.datastore.user_get_threepids(requester.user.to_string())

        return 200, {"threepids": threepids}

    async def on_POST(self, request):
        if not self.hs.config.enable_3pid_changes:
            raise SynapseError(
                400, "3PID changes are disabled on this server", Codes.FORBIDDEN
            )

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        threepid_creds = body.get("threePidCreds") or body.get("three_pid_creds")
        if threepid_creds is None:
            raise SynapseError(
                400, "Missing param three_pid_creds", Codes.MISSING_PARAM
            )
        assert_params_in_dict(threepid_creds, ["client_secret", "sid"])

        sid = threepid_creds["sid"]
        client_secret = threepid_creds["client_secret"]
        assert_valid_client_secret(client_secret)

        validation_session = await self.identity_handler.validate_threepid_session(
            client_secret, sid
        )
        if validation_session:
            await self.auth_handler.add_threepid(
                user_id,
                validation_session["medium"],
                validation_session["address"],
                validation_session["validated_at"],
            )
            return 200, {}

        raise SynapseError(
            400, "No validated 3pid session found", Codes.THREEPID_AUTH_FAILED
        )


class ThreepidAddRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/add$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    @interactive_auth_handler
    async def on_POST(self, request):
        if not self.hs.config.enable_3pid_changes:
            raise SynapseError(
                400, "3PID changes are disabled on this server", Codes.FORBIDDEN
            )

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["client_secret", "sid"])
        sid = body["sid"]
        client_secret = body["client_secret"]
        assert_valid_client_secret(client_secret)

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body,
            "add a third-party identifier to your account",
        )

        validation_session = await self.identity_handler.validate_threepid_session(
            client_secret, sid
        )
        if validation_session:
            await self.auth_handler.add_threepid(
                user_id,
                validation_session["medium"],
                validation_session["address"],
                validation_session["validated_at"],
            )
            return 200, {}

        raise SynapseError(
            400, "No validated 3pid session found", Codes.THREEPID_AUTH_FAILED
        )


class ThreepidBindRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/bind$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()

    async def on_POST(self, request):
        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["id_server", "sid", "client_secret"])
        id_server = body["id_server"]
        sid = body["sid"]
        id_access_token = body.get("id_access_token")  # optional
        client_secret = body["client_secret"]
        assert_valid_client_secret(client_secret)

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        await self.identity_handler.bind_threepid(
            client_secret, sid, user_id, id_server, id_access_token
        )

        return 200, {}


class ThreepidUnbindRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/unbind$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()
        self.datastore = self.hs.get_datastore()

    async def on_POST(self, request):
        """Unbind the given 3pid from a specific identity server, or identity servers that are
        known to have this 3pid bound
        """
        requester = await self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["medium", "address"])

        medium = body.get("medium")
        address = body.get("address")
        id_server = body.get("id_server")

        # Attempt to unbind the threepid from an identity server. If id_server is None, try to
        # unbind from all identity servers this threepid has been added to in the past
        result = await self.identity_handler.try_unbind_threepid(
            requester.user.to_string(),
            {"address": address, "medium": medium, "id_server": id_server},
        )
        return 200, {"id_server_unbind_result": "success" if result else "no-support"}


class ThreepidDeleteRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/delete$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    async def on_POST(self, request):
        if not self.hs.config.enable_3pid_changes:
            raise SynapseError(
                400, "3PID changes are disabled on this server", Codes.FORBIDDEN
            )

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["medium", "address"])

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        try:
            ret = await self.auth_handler.delete_threepid(
                user_id, body["medium"], body["address"], body.get("id_server")
            )
        except Exception:
            # NB. This endpoint should succeed if there is nothing to
            # delete, so it should only throw if something is wrong
            # that we ought to care about.
            logger.exception("Failed to remove threepid")
            raise SynapseError(500, "Failed to remove threepid")

        if ret:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        return 200, {"id_server_unbind_result": id_server_unbind_result}


def assert_valid_next_link(hs: "HomeServer", next_link: str):
    """
    Raises a SynapseError if a given next_link value is invalid

    next_link is valid if the scheme is http(s) and the next_link.domain_whitelist config
    option is either empty or contains a domain that matches the one in the given next_link

    Args:
        hs: The homeserver object
        next_link: The next_link value given by the client

    Raises:
        SynapseError: If the next_link is invalid
    """
    valid = True

    # Parse the contents of the URL
    next_link_parsed = urlparse(next_link)

    # Scheme must not point to the local drive
    if next_link_parsed.scheme == "file":
        valid = False

    # If the domain whitelist is set, the domain must be in it
    if (
        valid
        and hs.config.next_link_domain_whitelist is not None
        and next_link_parsed.hostname not in hs.config.next_link_domain_whitelist
    ):
        valid = False

    if not valid:
        raise SynapseError(
            400,
            "'next_link' domain not included in whitelist, or not http(s)",
            errcode=Codes.INVALID_PARAM,
        )


class WhoamiRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/whoami$")

    def __init__(self, hs):
        super().__init__()
        self.auth = hs.get_auth()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request)

        return 200, {"user_id": requester.user.to_string()}


def register_servlets(hs, http_server):
    EmailPasswordRequestTokenRestServlet(hs).register(http_server)
    PasswordRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    EmailThreepidRequestTokenRestServlet(hs).register(http_server)
    MsisdnThreepidRequestTokenRestServlet(hs).register(http_server)
    AddThreepidEmailSubmitTokenServlet(hs).register(http_server)
    AddThreepidMsisdnSubmitTokenServlet(hs).register(http_server)
    ThreepidRestServlet(hs).register(http_server)
    ThreepidAddRestServlet(hs).register(http_server)
    ThreepidBindRestServlet(hs).register(http_server)
    ThreepidUnbindRestServlet(hs).register(http_server)
    ThreepidDeleteRestServlet(hs).register(http_server)
    WhoamiRestServlet(hs).register(http_server)
