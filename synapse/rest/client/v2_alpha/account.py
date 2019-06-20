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

from six.moves import http_client

import jinja2

from twisted.internet import defer

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, SynapseError, ThreepidValidationError
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.stringutils import random_string
from synapse.util.threepids import check_3pid_allowed

from ._base import client_patterns, interactive_auth_handler

logger = logging.getLogger(__name__)


class EmailPasswordRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password/email/requestToken$")

    def __init__(self, hs):
        super(EmailPasswordRequestTokenRestServlet, self).__init__()
        self.hs = hs
        self.datastore = hs.get_datastore()
        self.config = hs.config
        self.identity_handler = hs.get_handlers().identity_handler

        if self.config.email_password_reset_behaviour == "local":
            from synapse.push.mailer import Mailer, load_jinja2_templates

            templates = load_jinja2_templates(
                config=hs.config,
                template_html_name=hs.config.email_password_reset_template_html,
                template_text_name=hs.config.email_password_reset_template_text,
            )
            self.mailer = Mailer(
                hs=self.hs,
                app_name=self.config.email_app_name,
                template_html=templates[0],
                template_text=templates[1],
            )

    @defer.inlineCallbacks
    def on_POST(self, request):
        if self.config.email_password_reset_behaviour == "off":
            if self.config.password_resets_were_disabled_due_to_email_config:
                logger.warn(
                    "User password resets have been disabled due to lack of email config"
                )
            raise SynapseError(
                400, "Email-based password resets have been disabled on this server"
            )

        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["client_secret", "email", "send_attempt"])

        # Extract params from body
        client_secret = body["client_secret"]
        email = body["email"]
        send_attempt = body["send_attempt"]
        next_link = body.get("next_link")  # Optional param

        if not check_3pid_allowed(self.hs, "email", email):
            raise SynapseError(
                403,
                "Your email domain is not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.hs.get_datastore().get_user_id_by_threepid(
            "email", email
        )

        if existingUid is None:
            raise SynapseError(400, "Email not found", Codes.THREEPID_NOT_FOUND)

        if self.config.email_password_reset_behaviour == "remote":
            if "id_server" not in body:
                raise SynapseError(400, "Missing 'id_server' param in body")

            # Have the identity server handle the password reset flow
            ret = yield self.identity_handler.requestEmailToken(
                body["id_server"], email, client_secret, send_attempt, next_link
            )
        else:
            # Send password reset emails from Synapse
            sid = yield self.send_password_reset(
                email, client_secret, send_attempt, next_link
            )

            # Wrap the session id in a JSON object
            ret = {"sid": sid}

        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def send_password_reset(self, email, client_secret, send_attempt, next_link=None):
        """Send a password reset email

        Args:
            email (str): The user's email address
            client_secret (str): The provided client secret
            send_attempt (int): Which send attempt this is

        Returns:
            The new session_id upon success

        Raises:
            SynapseError is an error occurred when sending the email
        """
        # Check that this email/client_secret/send_attempt combo is new or
        # greater than what we've seen previously
        session = yield self.datastore.get_threepid_validation_session(
            "email", client_secret, address=email, validated=False
        )

        # Check to see if a session already exists and that it is not yet
        # marked as validated
        if session and session.get("validated_at") is None:
            session_id = session["session_id"]
            last_send_attempt = session["last_send_attempt"]

            # Check that the send_attempt is higher than previous attempts
            if send_attempt <= last_send_attempt:
                # If not, just return a success without sending an email
                defer.returnValue(session_id)
        else:
            # An non-validated session does not exist yet.
            # Generate a session id
            session_id = random_string(16)

        # Generate a new validation token
        token = random_string(32)

        # Send the mail with the link containing the token, client_secret
        # and session_id
        try:
            yield self.mailer.send_password_reset_mail(
                email, token, client_secret, session_id
            )
        except Exception:
            logger.exception("Error sending a password reset email to %s", email)
            raise SynapseError(
                500, "An error was encountered when sending the password reset email"
            )

        token_expires = (
            self.hs.clock.time_msec() + self.config.email_validation_token_lifetime
        )

        yield self.datastore.start_or_continue_validation_session(
            "email",
            email,
            session_id,
            client_secret,
            send_attempt,
            next_link,
            token,
            token_expires,
        )

        defer.returnValue(session_id)


class MsisdnPasswordRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password/msisdn/requestToken$")

    def __init__(self, hs):
        super(MsisdnPasswordRequestTokenRestServlet, self).__init__()
        self.hs = hs
        self.datastore = self.hs.get_datastore()
        self.identity_handler = hs.get_handlers().identity_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        assert_params_in_dict(
            body,
            ["id_server", "client_secret", "country", "phone_number", "send_attempt"],
        )

        msisdn = phone_number_to_msisdn(body["country"], body["phone_number"])

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Account phone numbers are not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.datastore.get_user_id_by_threepid("msisdn", msisdn)

        if existingUid is None:
            raise SynapseError(400, "MSISDN not found", Codes.THREEPID_NOT_FOUND)

        ret = yield self.identity_handler.requestMsisdnToken(**body)
        defer.returnValue((200, ret))


class PasswordResetSubmitTokenServlet(RestServlet):
    """Handles 3PID validation token submission"""

    PATTERNS = client_patterns(
        "/password_reset/(?P<medium>[^/]*)/submit_token/*$", releases=(), unstable=True
    )

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(PasswordResetSubmitTokenServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.config = hs.config
        self.clock = hs.get_clock()
        self.datastore = hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request, medium):
        if medium != "email":
            raise SynapseError(
                400, "This medium is currently not supported for password resets"
            )
        if self.config.email_password_reset_behaviour == "off":
            if self.config.password_resets_were_disabled_due_to_email_config:
                logger.warn(
                    "User password resets have been disabled due to lack of email config"
                )
            raise SynapseError(
                400, "Email-based password resets have been disabled on this server"
            )

        sid = parse_string(request, "sid")
        client_secret = parse_string(request, "client_secret")
        token = parse_string(request, "token")

        # Attempt to validate a 3PID sesssion
        try:
            # Mark the session as valid
            next_link = yield self.datastore.validate_threepid_session(
                sid, client_secret, token, self.clock.time_msec()
            )

            # Perform a 302 redirect if next_link is set
            if next_link:
                if next_link.startswith("file:///"):
                    logger.warn(
                        "Not redirecting to next_link as it is a local file: address"
                    )
                else:
                    request.setResponseCode(302)
                    request.setHeader("Location", next_link)
                    finish_request(request)
                    defer.returnValue(None)

            # Otherwise show the success template
            html = self.config.email_password_reset_success_html_content
            request.setResponseCode(200)
        except ThreepidValidationError as e:
            # Show a failure page with a reason
            html = self.load_jinja2_template(
                self.config.email_template_dir,
                self.config.email_password_reset_failure_template,
                template_vars={"failure_reason": e.msg},
            )
            request.setResponseCode(e.code)

        request.write(html.encode("utf-8"))
        finish_request(request)
        defer.returnValue(None)

    def load_jinja2_template(self, template_dir, template_filename, template_vars):
        """Loads a jinja2 template with variables to insert

        Args:
            template_dir (str): The directory where templates are stored
            template_filename (str): The name of the template in the template_dir
            template_vars (Dict): Dictionary of keys in the template
                alongside their values to insert

        Returns:
            str containing the contents of the rendered template
        """
        loader = jinja2.FileSystemLoader(template_dir)
        env = jinja2.Environment(loader=loader)

        template = env.get_template(template_filename)
        return template.render(**template_vars)

    @defer.inlineCallbacks
    def on_POST(self, request, medium):
        if medium != "email":
            raise SynapseError(
                400, "This medium is currently not supported for password resets"
            )

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["sid", "client_secret", "token"])

        valid, _ = yield self.datastore.validate_threepid_validation_token(
            body["sid"], body["client_secret"], body["token"], self.clock.time_msec()
        )
        response_code = 200 if valid else 400

        defer.returnValue((response_code, {"success": valid}))


class PasswordRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/password$")

    def __init__(self, hs):
        super(PasswordRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastore()
        self._set_password_handler = hs.get_set_password_handler()

    @interactive_auth_handler
    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

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
            requester = yield self.auth.get_user_by_req(request)
            params = yield self.auth_handler.validate_user_via_ui_auth(
                requester, body, self.hs.get_ip_from_request(request)
            )
            user_id = requester.user.to_string()
        else:
            requester = None
            result, params, _ = yield self.auth_handler.check_auth(
                [[LoginType.EMAIL_IDENTITY], [LoginType.MSISDN]],
                body,
                self.hs.get_ip_from_request(request),
                password_servlet=True,
            )

            if LoginType.EMAIL_IDENTITY in result:
                threepid = result[LoginType.EMAIL_IDENTITY]
                if "medium" not in threepid or "address" not in threepid:
                    raise SynapseError(500, "Malformed threepid")
                if threepid["medium"] == "email":
                    # For emails, transform the address to lowercase.
                    # We store all email addreses as lowercase in the DB.
                    # (See add_threepid in synapse/handlers/auth.py)
                    threepid["address"] = threepid["address"].lower()
                # if using email, we must know about the email they're authing with!
                threepid_user_id = yield self.datastore.get_user_id_by_threepid(
                    threepid["medium"], threepid["address"]
                )
                if not threepid_user_id:
                    raise SynapseError(404, "Email address not found", Codes.NOT_FOUND)
                user_id = threepid_user_id
            else:
                logger.error("Auth succeeded but no known type! %r", result.keys())
                raise SynapseError(500, "", Codes.UNKNOWN)

        assert_params_in_dict(params, ["new_password"])
        new_password = params["new_password"]

        yield self._set_password_handler.set_password(user_id, new_password, requester)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


class DeactivateAccountRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/deactivate$")

    def __init__(self, hs):
        super(DeactivateAccountRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self._deactivate_account_handler = hs.get_deactivate_account_handler()

    @interactive_auth_handler
    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise SynapseError(
                http_client.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        requester = yield self.auth.get_user_by_req(request)

        # allow ASes to dectivate their own users
        if requester.app_service:
            yield self._deactivate_account_handler.deactivate_account(
                requester.user.to_string(), erase
            )
            defer.returnValue((200, {}))

        yield self.auth_handler.validate_user_via_ui_auth(
            requester, body, self.hs.get_ip_from_request(request)
        )
        result = yield self._deactivate_account_handler.deactivate_account(
            requester.user.to_string(), erase, id_server=body.get("id_server")
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        defer.returnValue((200, {"id_server_unbind_result": id_server_unbind_result}))


class EmailThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/email/requestToken$")

    def __init__(self, hs):
        self.hs = hs
        super(EmailThreepidRequestTokenRestServlet, self).__init__()
        self.identity_handler = hs.get_handlers().identity_handler
        self.datastore = self.hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(
            body, ["id_server", "client_secret", "email", "send_attempt"]
        )

        if not check_3pid_allowed(self.hs, "email", body["email"]):
            raise SynapseError(
                403,
                "Your email domain is not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.datastore.get_user_id_by_threepid(
            "email", body["email"]
        )

        if existingUid is not None:
            raise SynapseError(400, "Email is already in use", Codes.THREEPID_IN_USE)

        ret = yield self.identity_handler.requestEmailToken(**body)
        defer.returnValue((200, ret))


class MsisdnThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/msisdn/requestToken$")

    def __init__(self, hs):
        self.hs = hs
        super(MsisdnThreepidRequestTokenRestServlet, self).__init__()
        self.identity_handler = hs.get_handlers().identity_handler
        self.datastore = self.hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(
            body,
            ["id_server", "client_secret", "country", "phone_number", "send_attempt"],
        )

        msisdn = phone_number_to_msisdn(body["country"], body["phone_number"])

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Account phone numbers are not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.datastore.get_user_id_by_threepid("msisdn", msisdn)

        if existingUid is not None:
            raise SynapseError(400, "MSISDN is already in use", Codes.THREEPID_IN_USE)

        ret = yield self.identity_handler.requestMsisdnToken(**body)
        defer.returnValue((200, ret))


class ThreepidRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid$")

    def __init__(self, hs):
        super(ThreepidRestServlet, self).__init__()
        self.hs = hs
        self.identity_handler = hs.get_handlers().identity_handler
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)

        threepids = yield self.datastore.user_get_threepids(requester.user.to_string())

        defer.returnValue((200, {"threepids": threepids}))

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        threePidCreds = body.get("threePidCreds")
        threePidCreds = body.get("three_pid_creds", threePidCreds)
        if threePidCreds is None:
            raise SynapseError(400, "Missing param", Codes.MISSING_PARAM)

        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        threepid = yield self.identity_handler.threepid_from_creds(threePidCreds)

        if not threepid:
            raise SynapseError(400, "Failed to auth 3pid", Codes.THREEPID_AUTH_FAILED)

        for reqd in ["medium", "address", "validated_at"]:
            if reqd not in threepid:
                logger.warn("Couldn't add 3pid: invalid response from ID server")
                raise SynapseError(500, "Invalid response from ID Server")

        yield self.auth_handler.add_threepid(
            user_id, threepid["medium"], threepid["address"], threepid["validated_at"]
        )

        if "bind" in body and body["bind"]:
            logger.debug("Binding threepid %s to %s", threepid, user_id)
            yield self.identity_handler.bind_threepid(threePidCreds, user_id)

        defer.returnValue((200, {}))


class ThreepidDeleteRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/3pid/delete$")

    def __init__(self, hs):
        super(ThreepidDeleteRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["medium", "address"])

        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        try:
            ret = yield self.auth_handler.delete_threepid(
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

        defer.returnValue((200, {"id_server_unbind_result": id_server_unbind_result}))


class WhoamiRestServlet(RestServlet):
    PATTERNS = client_patterns("/account/whoami$")

    def __init__(self, hs):
        super(WhoamiRestServlet, self).__init__()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)

        defer.returnValue((200, {"user_id": requester.user.to_string()}))


def register_servlets(hs, http_server):
    EmailPasswordRequestTokenRestServlet(hs).register(http_server)
    MsisdnPasswordRequestTokenRestServlet(hs).register(http_server)
    PasswordResetSubmitTokenServlet(hs).register(http_server)
    PasswordRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    EmailThreepidRequestTokenRestServlet(hs).register(http_server)
    MsisdnThreepidRequestTokenRestServlet(hs).register(http_server)
    ThreepidRestServlet(hs).register(http_server)
    ThreepidDeleteRestServlet(hs).register(http_server)
    WhoamiRestServlet(hs).register(http_server)
