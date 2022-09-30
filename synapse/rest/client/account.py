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
from typing import TYPE_CHECKING, List, Optional, Tuple
from urllib.parse import urlparse

from pydantic import StrictBool, StrictStr, constr
from typing_extensions import Literal

from twisted.web.server import Request

from synapse.api.constants import LoginType
from synapse.api.errors import (
    Codes,
    InteractiveAuthIncompleteError,
    SynapseError,
    ThreepidValidationError,
)
from synapse.handlers.ui_auth import UIAuthSessionDataConstants
from synapse.http.server import HttpServer, finish_request, respond_with_html
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_and_validate_json_object_from_request,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.metrics import threepid_send_requests
from synapse.push.mailer import Mailer
from synapse.rest.client.models import (
    AuthenticationData,
    ClientSecretStr,
    EmailRequestTokenBody,
    MsisdnRequestTokenBody,
)
from synapse.rest.models import RequestBodyModel
from synapse.types import JsonDict
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.stringutils import assert_valid_client_secret, random_string
from synapse.util.threepids import check_3pid_allowed, validate_email

from ._base import client_patterns, interactive_auth_handler

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class EmailPasswordRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password/email/requestToken$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.datastore = hs.get_datastores().main
        self.config = hs.config
        self.identity_handler = hs.get_identity_handler()

        if self.config.email.can_verify_email:
            self.mailer = Mailer(
                hs=self.hs,
                app_name=self.config.email.email_app_name,
                template_html=self.config.email.email_password_reset_template_html,
                template_text=self.config.email.email_password_reset_template_text,
            )

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if not self.config.email.can_verify_email:
            logger.warning(
                "User password resets have been disabled due to lack of email config"
            )
            raise SynapseError(
                400, "Email-based password resets have been disabled on this server"
            )

        body = parse_and_validate_json_object_from_request(
            request, EmailRequestTokenBody
        )

        if body.next_link:
            # Raise if the provided next_link value isn't valid
            assert_valid_next_link(self.hs, body.next_link)

        await self.identity_handler.ratelimit_request_token_requests(
            request, "email", body.email
        )

        # The email will be sent to the stored address.
        # This avoids a potential account hijack by requesting a password reset to
        # an email address which is controlled by the attacker but which, after
        # canonicalisation, matches the one in our database.
        existing_user_id = await self.hs.get_datastores().main.get_user_id_by_threepid(
            "email", body.email
        )

        if existing_user_id is None:
            if self.config.server.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "Email not found", Codes.THREEPID_NOT_FOUND)

        # Send password reset emails from Synapse
        sid = await self.identity_handler.send_threepid_validation(
            body.email,
            body.client_secret,
            body.send_attempt,
            self.mailer.send_password_reset_mail,
            body.next_link,
        )
        threepid_send_requests.labels(type="email", reason="password_reset").observe(
            body.send_attempt
        )

        # Wrap the session id in a JSON object
        return 200, {"sid": sid}


class PasswordRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastores().main
        self.password_policy_handler = hs.get_password_policy_handler()
        self._set_password_handler = hs.get_set_password_handler()

    class PostBody(RequestBodyModel):
        auth: Optional[AuthenticationData] = None
        logout_devices: StrictBool = True
        if TYPE_CHECKING:
            # workaround for https://github.com/samuelcolvin/pydantic/issues/156
            new_password: Optional[StrictStr] = None
        else:
            new_password: Optional[constr(max_length=512, strict=True)] = None

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        # we do basic sanity checks here because the auth layer will store these
        # in sessions. Pull out the new password provided to us.
        new_password = body.new_password
        if new_password is not None:
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

        requester = None
        if self.auth.has_access_token(request):
            requester = await self.auth.get_user_by_req(request)
            try:
                params, session_id = await self.auth_handler.validate_user_via_ui_auth(
                    requester,
                    request,
                    body.dict(exclude_unset=True),
                    "modify your account password",
                )
            except InteractiveAuthIncompleteError as e:
                # The user needs to provide more steps to complete auth, but
                # they're not required to provide the password again.
                #
                # If a password is available now, hash the provided password and
                # store it for later.
                if new_password:
                    new_password_hash = await self.auth_handler.hash(new_password)
                    await self.auth_handler.set_session_data(
                        e.session_id,
                        UIAuthSessionDataConstants.PASSWORD_HASH,
                        new_password_hash,
                    )
                raise
            user_id = requester.user.to_string()
        else:
            try:
                result, params, session_id = await self.auth_handler.check_ui_auth(
                    [[LoginType.EMAIL_IDENTITY]],
                    request,
                    body.dict(exclude_unset=True),
                    "modify your account password",
                )
            except InteractiveAuthIncompleteError as e:
                # The user needs to provide more steps to complete auth, but
                # they're not required to provide the password again.
                #
                # If a password is available now, hash the provided password and
                # store it for later.
                if new_password:
                    new_password_hash = await self.auth_handler.hash(new_password)
                    await self.auth_handler.set_session_data(
                        e.session_id,
                        UIAuthSessionDataConstants.PASSWORD_HASH,
                        new_password_hash,
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
                        threepid["address"] = validate_email(threepid["address"])
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
            password_hash: Optional[str] = await self.auth_handler.hash(new_password)
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

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self._deactivate_account_handler = hs.get_deactivate_account_handler()

    class PostBody(RequestBodyModel):
        auth: Optional[AuthenticationData] = None
        id_server: Optional[StrictStr] = None
        # Not specced, see https://github.com/matrix-org/matrix-spec/issues/297
        erase: StrictBool = False

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        requester = await self.auth.get_user_by_req(request)

        # allow ASes to deactivate their own users
        if requester.app_service:
            await self._deactivate_account_handler.deactivate_account(
                requester.user.to_string(), body.erase, requester
            )
            return 200, {}

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body.dict(exclude_unset=True),
            "deactivate your account",
        )
        result = await self._deactivate_account_handler.deactivate_account(
            requester.user.to_string(), body.erase, requester, id_server=body.id_server
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        return 200, {"id_server_unbind_result": id_server_unbind_result}


class EmailThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/email/requestToken$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.config = hs.config
        self.identity_handler = hs.get_identity_handler()
        self.store = self.hs.get_datastores().main

        if self.config.email.can_verify_email:
            self.mailer = Mailer(
                hs=self.hs,
                app_name=self.config.email.email_app_name,
                template_html=self.config.email.email_add_threepid_template_html,
                template_text=self.config.email.email_add_threepid_template_text,
            )

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if not self.config.email.can_verify_email:
            logger.warning(
                "Adding emails have been disabled due to lack of an email config"
            )
            raise SynapseError(
                400,
                "Adding an email to your account is disabled on this server",
            )

        body = parse_and_validate_json_object_from_request(
            request, EmailRequestTokenBody
        )

        if not await check_3pid_allowed(self.hs, "email", body.email):
            raise SynapseError(
                403,
                "Your email domain is not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        await self.identity_handler.ratelimit_request_token_requests(
            request, "email", body.email
        )

        if body.next_link:
            # Raise if the provided next_link value isn't valid
            assert_valid_next_link(self.hs, body.next_link)

        existing_user_id = await self.store.get_user_id_by_threepid("email", body.email)

        if existing_user_id is not None:
            if self.config.server.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "Email is already in use", Codes.THREEPID_IN_USE)

        # Send threepid validation emails from Synapse
        sid = await self.identity_handler.send_threepid_validation(
            body.email,
            body.client_secret,
            body.send_attempt,
            self.mailer.send_add_threepid_mail,
            body.next_link,
        )

        threepid_send_requests.labels(type="email", reason="add_threepid").observe(
            body.send_attempt
        )

        # Wrap the session id in a JSON object
        return 200, {"sid": sid}


class MsisdnThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/msisdn/requestToken$")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        super().__init__()
        self.store = self.hs.get_datastores().main
        self.identity_handler = hs.get_identity_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        body = parse_and_validate_json_object_from_request(
            request, MsisdnRequestTokenBody
        )
        msisdn = phone_number_to_msisdn(body.country, body.phone_number)

        if not await check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                # TODO: is this error message accurate? Looks like we've only rejected
                #       this phone number, not necessarily all phone numbers
                "Account phone numbers are not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        await self.identity_handler.ratelimit_request_token_requests(
            request, "msisdn", msisdn
        )

        if body.next_link:
            # Raise if the provided next_link value isn't valid
            assert_valid_next_link(self.hs, body.next_link)

        existing_user_id = await self.store.get_user_id_by_threepid("msisdn", msisdn)

        if existing_user_id is not None:
            if self.hs.config.server.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "MSISDN is already in use", Codes.THREEPID_IN_USE)

        if not self.hs.config.registration.account_threepid_delegate_msisdn:
            logger.warning(
                "No upstream msisdn account_threepid_delegate configured on the server to "
                "handle this request"
            )
            raise SynapseError(
                400,
                "Adding phone numbers to user account is not supported by this homeserver",
            )

        ret = await self.identity_handler.requestMsisdnToken(
            self.hs.config.registration.account_threepid_delegate_msisdn,
            body.country,
            body.phone_number,
            body.client_secret,
            body.send_attempt,
            body.next_link,
        )

        threepid_send_requests.labels(type="msisdn", reason="add_threepid").observe(
            body.send_attempt
        )

        return 200, ret


class AddThreepidEmailSubmitTokenServlet(RestServlet):
    """Handles 3PID validation token submission for adding an email to a user's account"""

    PATTERNS = client_patterns(
        "/add_threepid/email/submit_token$", releases=(), unstable=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.config = hs.config
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        if self.config.email.can_verify_email:
            self._failure_email_template = (
                self.config.email.email_add_threepid_template_failure_html
            )

    async def on_GET(self, request: Request) -> None:
        if not self.config.email.can_verify_email:
            logger.warning(
                "Adding emails have been disabled due to lack of an email config"
            )
            raise SynapseError(
                400, "Adding an email to your account is disabled on this server"
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
            html = self.config.email.email_add_threepid_template_success_html_content
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

    class PostBody(RequestBodyModel):
        client_secret: ClientSecretStr
        sid: StrictStr
        token: StrictStr

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.config = hs.config
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self.identity_handler = hs.get_identity_handler()

    async def on_POST(self, request: Request) -> Tuple[int, JsonDict]:
        if not self.config.registration.account_threepid_delegate_msisdn:
            raise SynapseError(
                400,
                "This homeserver is not validating phone numbers. Use an identity server "
                "instead.",
            )

        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        # Proxy submit_token request to msisdn threepid delegate
        response = await self.identity_handler.proxy_msisdn_submit_token(
            self.config.registration.account_threepid_delegate_msisdn,
            body.client_secret,
            body.sid,
            body.token,
        )
        return 200, response


class ThreepidRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        threepids = await self.datastore.user_get_threepids(requester.user.to_string())

        return 200, {"threepids": threepids}

    # NOTE(dmr): I have chosen not to use Pydantic to parse this request's body, because
    # the endpoint is deprecated. (If you really want to, you could do this by reusing
    # ThreePidBindRestServelet.PostBody with an `alias_generator` to handle
    # `threePidCreds` versus `three_pid_creds`.
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if not self.hs.config.registration.enable_3pid_changes:
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

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    class PostBody(RequestBodyModel):
        auth: Optional[AuthenticationData] = None
        client_secret: ClientSecretStr
        sid: StrictStr

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if not self.hs.config.registration.enable_3pid_changes:
            raise SynapseError(
                400, "3PID changes are disabled on this server", Codes.FORBIDDEN
            )

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()
        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body.dict(exclude_unset=True),
            "add a third-party identifier to your account",
        )

        validation_session = await self.identity_handler.validate_threepid_session(
            body.client_secret, body.sid
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

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()

    class PostBody(RequestBodyModel):
        client_secret: ClientSecretStr
        id_access_token: StrictStr
        id_server: StrictStr
        sid: StrictStr

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        await self.identity_handler.bind_threepid(
            body.client_secret, body.sid, user_id, body.id_server, body.id_access_token
        )

        return 200, {}


class ThreepidUnbindRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/unbind$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.auth = hs.get_auth()
        self.datastore = self.hs.get_datastores().main

    class PostBody(RequestBodyModel):
        address: StrictStr
        id_server: Optional[StrictStr] = None
        medium: Literal["email", "msisdn"]

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        """Unbind the given 3pid from a specific identity server, or identity servers that are
        known to have this 3pid bound
        """
        requester = await self.auth.get_user_by_req(request)
        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        # Attempt to unbind the threepid from an identity server. If id_server is None, try to
        # unbind from all identity servers this threepid has been added to in the past
        result = await self.identity_handler.try_unbind_threepid(
            requester.user.to_string(),
            {
                "address": body.address,
                "medium": body.medium,
                "id_server": body.id_server,
            },
        )
        return 200, {"id_server_unbind_result": "success" if result else "no-support"}


class ThreepidDeleteRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/delete$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    class PostBody(RequestBodyModel):
        address: StrictStr
        id_server: Optional[StrictStr] = None
        medium: Literal["email", "msisdn"]

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if not self.hs.config.registration.enable_3pid_changes:
            raise SynapseError(
                400, "3PID changes are disabled on this server", Codes.FORBIDDEN
            )

        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        try:
            ret = await self.auth_handler.delete_threepid(
                user_id, body.medium, body.address, body.id_server
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


def assert_valid_next_link(hs: "HomeServer", next_link: str) -> None:
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
        and hs.config.server.next_link_domain_whitelist is not None
        and next_link_parsed.hostname not in hs.config.server.next_link_domain_whitelist
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

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        response = {
            "user_id": requester.user.to_string(),
            # Entered spec in Matrix 1.2
            "is_guest": bool(requester.is_guest),
        }

        # Appservices and similar accounts do not have device IDs
        # that we can report on, so exclude them for compliance.
        if requester.device_id is not None:
            response["device_id"] = requester.device_id

        return 200, response


class AccountStatusRestServlet(RestServlet):
    PATTERNS = client_patterns(
        "/org.matrix.msc3720/account_status$", unstable=True, releases=()
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._auth = hs.get_auth()
        self._account_handler = hs.get_account_handler()

    class PostBody(RequestBodyModel):
        # TODO: we could validate that each user id is an mxid here, and/or parse it
        #       as a UserID
        user_ids: List[StrictStr]

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self._auth.get_user_by_req(request)

        body = parse_and_validate_json_object_from_request(request, self.PostBody)

        statuses, failures = await self._account_handler.get_account_statuses(
            body.user_ids,
            allow_remote=True,
        )

        return 200, {"account_statuses": statuses, "failures": failures}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
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

    if hs.config.experimental.msc3720_enabled:
        AccountStatusRestServlet(hs).register(http_server)
