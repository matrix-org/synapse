# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""This module contains REST servlets to do with registration: /register"""
import hmac
import logging
from hashlib import sha1

from twisted.internet import defer

import synapse.util.stringutils as stringutils
from synapse.api.constants import LoginType
from synapse.api.errors import Codes, SynapseError
from synapse.config.server import is_threepid_reserved
from synapse.http.servlet import assert_params_in_dict, parse_json_object_from_request
from synapse.rest.client.v1.base import ClientV1RestServlet
from synapse.types import create_requester

from .base import v1_only_client_path_patterns

logger = logging.getLogger(__name__)


# We ought to be using hmac.compare_digest() but on older pythons it doesn't
# exist. It's a _really minor_ security flaw to use plain string comparison
# because the timing attack is so obscured by all the other code here it's
# unlikely to make much difference
if hasattr(hmac, "compare_digest"):
    compare_digest = hmac.compare_digest
else:
    def compare_digest(a, b):
        return a == b


class RegisterRestServlet(ClientV1RestServlet):
    """Handles registration with the home server.

    This servlet is in control of the registration flow; the registration
    handler doesn't have a concept of multi-stages or sessions.
    """

    PATTERNS = v1_only_client_path_patterns("/register$", include_in_unstable=False)

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(RegisterRestServlet, self).__init__(hs)
        # sessions are stored as:
        # self.sessions = {
        #   "session_id" : { __session_dict__ }
        # }
        # TODO: persistent storage
        self.sessions = {}
        self.enable_registration = hs.config.enable_registration
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.handlers = hs.get_handlers()

    def on_GET(self, request):

        require_email = 'email' in self.hs.config.registrations_require_3pid
        require_msisdn = 'msisdn' in self.hs.config.registrations_require_3pid

        flows = []
        if self.hs.config.enable_registration_captcha:
            # only support the email-only flow if we don't require MSISDN 3PIDs
            if not require_msisdn:
                flows.extend([
                    {
                        "type": LoginType.RECAPTCHA,
                        "stages": [
                            LoginType.RECAPTCHA,
                            LoginType.EMAIL_IDENTITY,
                            LoginType.PASSWORD
                        ]
                    },
                ])
            # only support 3PIDless registration if no 3PIDs are required
            if not require_email and not require_msisdn:
                flows.extend([
                    {
                        "type": LoginType.RECAPTCHA,
                        "stages": [LoginType.RECAPTCHA, LoginType.PASSWORD]
                    }
                ])
        else:
            # only support the email-only flow if we don't require MSISDN 3PIDs
            if require_email or not require_msisdn:
                flows.extend([
                    {
                        "type": LoginType.EMAIL_IDENTITY,
                        "stages": [
                            LoginType.EMAIL_IDENTITY, LoginType.PASSWORD
                        ]
                    }
                ])
            # only support 3PIDless registration if no 3PIDs are required
            if not require_email and not require_msisdn:
                flows.extend([
                    {
                        "type": LoginType.PASSWORD
                    }
                ])
        return (200, {"flows": flows})

    @defer.inlineCallbacks
    def on_POST(self, request):
        register_json = parse_json_object_from_request(request)

        session = (register_json["session"]
                   if "session" in register_json else None)
        login_type = None
        assert_params_in_dict(register_json, ["type"])

        try:
            login_type = register_json["type"]

            is_application_server = login_type == LoginType.APPLICATION_SERVICE
            can_register = (
                self.enable_registration
                or is_application_server
            )
            if not can_register:
                raise SynapseError(403, "Registration has been disabled")

            stages = {
                LoginType.RECAPTCHA: self._do_recaptcha,
                LoginType.PASSWORD: self._do_password,
                LoginType.EMAIL_IDENTITY: self._do_email_identity,
                LoginType.APPLICATION_SERVICE: self._do_app_service,
            }

            session_info = self._get_session_info(request, session)
            logger.debug("%s : session info %s   request info %s",
                         login_type, session_info, register_json)
            response = yield stages[login_type](
                request,
                register_json,
                session_info
            )

            if "access_token" not in response:
                # isn't a final response
                response["session"] = session_info["id"]

            defer.returnValue((200, response))
        except KeyError as e:
            logger.exception(e)
            raise SynapseError(400, "Missing JSON keys for login type %s." % (
                login_type,
            ))

    def on_OPTIONS(self, request):
        return (200, {})

    def _get_session_info(self, request, session_id):
        if not session_id:
            # create a new session
            while session_id is None or session_id in self.sessions:
                session_id = stringutils.random_string(24)
            self.sessions[session_id] = {
                "id": session_id,
                LoginType.EMAIL_IDENTITY: False,
                LoginType.RECAPTCHA: False
            }

        return self.sessions[session_id]

    def _save_session(self, session):
        # TODO: Persistent storage
        logger.debug("Saving session %s", session)
        self.sessions[session["id"]] = session

    def _remove_session(self, session):
        logger.debug("Removing session %s", session)
        self.sessions.pop(session["id"])

    @defer.inlineCallbacks
    def _do_recaptcha(self, request, register_json, session):
        if not self.hs.config.enable_registration_captcha:
            raise SynapseError(400, "Captcha not required.")

        yield self._check_recaptcha(request, register_json, session)

        session[LoginType.RECAPTCHA] = True  # mark captcha as done
        self._save_session(session)
        defer.returnValue({
            "next": [LoginType.PASSWORD, LoginType.EMAIL_IDENTITY]
        })

    @defer.inlineCallbacks
    def _check_recaptcha(self, request, register_json, session):
        if ("captcha_bypass_hmac" in register_json and
                self.hs.config.captcha_bypass_secret):
            if "user" not in register_json:
                raise SynapseError(400, "Captcha bypass needs 'user'")

            want = hmac.new(
                key=self.hs.config.captcha_bypass_secret,
                msg=register_json["user"],
                digestmod=sha1,
            ).hexdigest()

            # str() because otherwise hmac complains that 'unicode' does not
            # have the buffer interface
            got = str(register_json["captcha_bypass_hmac"])

            if compare_digest(want, got):
                session["user"] = register_json["user"]
                defer.returnValue(None)
            else:
                raise SynapseError(
                    400, "Captcha bypass HMAC incorrect",
                    errcode=Codes.CAPTCHA_NEEDED
                )

        challenge = None
        user_response = None
        try:
            challenge = register_json["challenge"]
            user_response = register_json["response"]
        except KeyError:
            raise SynapseError(400, "Captcha response is required",
                               errcode=Codes.CAPTCHA_NEEDED)

        ip_addr = self.hs.get_ip_from_request(request)

        handler = self.handlers.registration_handler
        yield handler.check_recaptcha(
            ip_addr,
            self.hs.config.recaptcha_private_key,
            challenge,
            user_response
        )

    @defer.inlineCallbacks
    def _do_email_identity(self, request, register_json, session):
        if (self.hs.config.enable_registration_captcha and
                not session[LoginType.RECAPTCHA]):
            raise SynapseError(400, "Captcha is required.")

        threepidCreds = register_json['threepidCreds']
        handler = self.handlers.registration_handler
        logger.debug("Registering email. threepidcreds: %s" % (threepidCreds))
        yield handler.register_email(threepidCreds)
        session["threepidCreds"] = threepidCreds  # store creds for next stage
        session[LoginType.EMAIL_IDENTITY] = True  # mark email as done
        self._save_session(session)
        defer.returnValue({
            "next": LoginType.PASSWORD
        })

    @defer.inlineCallbacks
    def _do_password(self, request, register_json, session):
        if (self.hs.config.enable_registration_captcha and
                not session[LoginType.RECAPTCHA]):
            # captcha should've been done by this stage!
            raise SynapseError(400, "Captcha is required.")

        if ("user" in session and "user" in register_json and
                session["user"] != register_json["user"]):
            raise SynapseError(
                400, "Cannot change user ID during registration"
            )

        password = register_json["password"].encode("utf-8")
        desired_user_id = (
            register_json["user"].encode("utf-8")
            if "user" in register_json else None
        )
        threepid = None
        if session.get(LoginType.EMAIL_IDENTITY):
            threepid = session["threepidCreds"]

        handler = self.handlers.registration_handler
        (user_id, token) = yield handler.register(
            localpart=desired_user_id,
            password=password,
            threepid=threepid,
        )
        # Necessary due to auth checks prior to the threepid being
        # written to the db
        if is_threepid_reserved(self.hs.config, threepid):
            yield self.store.upsert_monthly_active_user(user_id)

        if session[LoginType.EMAIL_IDENTITY]:
            logger.debug("Binding emails %s to %s" % (
                session["threepidCreds"], user_id)
            )
            yield handler.bind_emails(user_id, session["threepidCreds"])

        result = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        }
        self._remove_session(session)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def _do_app_service(self, request, register_json, session):
        as_token = self.auth.get_access_token_from_request(request)

        assert_params_in_dict(register_json, ["user"])
        user_localpart = register_json["user"].encode("utf-8")

        handler = self.handlers.registration_handler
        user_id = yield handler.appservice_register(
            user_localpart, as_token
        )
        token = yield self.auth_handler.issue_access_token(user_id)
        self._remove_session(session)
        defer.returnValue({
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        })


class CreateUserRestServlet(ClientV1RestServlet):
    """Handles user creation via a server-to-server interface
    """

    PATTERNS = v1_only_client_path_patterns("/createUser$")

    def __init__(self, hs):
        super(CreateUserRestServlet, self).__init__(hs)
        self.store = hs.get_datastore()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_POST(self, request):
        user_json = parse_json_object_from_request(request)

        access_token = self.auth.get_access_token_from_request(request)
        app_service = self.store.get_app_service_by_token(
            access_token
        )
        if not app_service:
            raise SynapseError(403, "Invalid application service token.")

        requester = create_requester(app_service.sender)

        logger.debug("creating user: %s", user_json)
        response = yield self._do_create(requester, user_json)

        defer.returnValue((200, response))

    def on_OPTIONS(self, request):
        return 403, {}

    @defer.inlineCallbacks
    def _do_create(self, requester, user_json):
        assert_params_in_dict(user_json, ["localpart", "displayname"])

        localpart = user_json["localpart"].encode("utf-8")
        displayname = user_json["displayname"].encode("utf-8")
        password_hash = user_json["password_hash"].encode("utf-8") \
            if user_json.get("password_hash") else None

        handler = self.handlers.registration_handler
        user_id, token = yield handler.get_or_create_user(
            requester=requester,
            localpart=localpart,
            displayname=displayname,
            password_hash=password_hash
        )

        defer.returnValue({
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        })


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)
    CreateUserRestServlet(hs).register(http_server)
