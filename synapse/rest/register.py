# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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
from twisted.internet import defer

from synapse.api.errors import SynapseError, Codes
from synapse.api.constants import LoginType
from base import RestServlet, client_path_pattern
import synapse.util.stringutils as stringutils

import json
import logging
import urllib

logger = logging.getLogger(__name__)


class RegisterRestServlet(RestServlet):
    """Handles registration with the home server.

    This servlet is in control of the registration flow; the registration
    handler doesn't have a concept of multi-stages or sessions.
    """

    PATTERN = client_path_pattern("/register$")

    def __init__(self, hs):
        super(RegisterRestServlet, self).__init__(hs)
        # sessions are stored as:
        # self.sessions = {
        #   "session_id" : { __session_dict__ }
        # }
        # TODO: persistent storage
        self.sessions = {}

    def on_GET(self, request):
        if self.hs.config.enable_registration_captcha:
            return (200, {
                "flows": [
                    {
                        "type": LoginType.RECAPTCHA,
                        "stages": ([LoginType.RECAPTCHA,
                                    LoginType.EMAIL_IDENTITY,
                                    LoginType.PASSWORD])
                    },
                    {
                        "type": LoginType.RECAPTCHA,
                        "stages": [LoginType.RECAPTCHA, LoginType.PASSWORD]
                    }
                ]
            })
        else:
            return (200, {
                "flows": [
                    {
                        "type": LoginType.EMAIL_IDENTITY,
                        "stages": ([LoginType.EMAIL_IDENTITY,
                                    LoginType.PASSWORD])
                    },
                    {
                        "type": LoginType.PASSWORD
                    }
                ]
            })

    @defer.inlineCallbacks
    def on_POST(self, request):
        register_json = _parse_json(request)

        session = (register_json["session"] if "session" in register_json
                  else None)
        login_type = None
        if "type" not in register_json:
            raise SynapseError(400, "Missing 'type' key.")

        try:
            login_type = register_json["type"]
            stages = {
                LoginType.RECAPTCHA: self._do_recaptcha,
                LoginType.PASSWORD: self._do_password,
                LoginType.EMAIL_IDENTITY: self._do_email_identity
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
            raise SynapseError(400, "Missing JSON keys for login type %s." % login_type)

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

        challenge = None
        user_response = None
        try:
            challenge = register_json["challenge"]
            user_response = register_json["response"]
        except KeyError:
            raise SynapseError(400, "Captcha response is required",
                               errcode=Codes.CAPTCHA_NEEDED)

        # May be an X-Forwarding-For header depending on config
        ip_addr = request.getClientIP()
        if self.hs.config.captcha_ip_origin_is_x_forwarded:
            # use the header
            if request.requestHeaders.hasHeader("X-Forwarded-For"):
                ip_addr = request.requestHeaders.getRawHeaders(
                    "X-Forwarded-For")[0]

        handler = self.handlers.registration_handler
        yield handler.check_recaptcha(
            ip_addr,
            self.hs.config.recaptcha_private_key,
            challenge,
            user_response
        )
        session[LoginType.RECAPTCHA] = True  # mark captcha as done
        self._save_session(session)
        defer.returnValue({
            "next": [LoginType.PASSWORD, LoginType.EMAIL_IDENTITY]
        })

    @defer.inlineCallbacks
    def _do_email_identity(self, request, register_json, session):
        if (self.hs.config.enable_registration_captcha and
                not session[LoginType.RECAPTCHA]):
            raise SynapseError(400, "Captcha is required.")

        threepidCreds = register_json['threepidCreds']
        handler = self.handlers.registration_handler
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

        password = register_json["password"].encode("utf-8")
        desired_user_id = (register_json["user"].encode("utf-8") if "user"
                          in register_json else None)
        if desired_user_id and urllib.quote(desired_user_id) != desired_user_id:
            raise SynapseError(
                400,
                "User ID must only contain characters which do not " +
                "require URL encoding.")
        handler = self.handlers.registration_handler
        (user_id, token) = yield handler.register(
            localpart=desired_user_id,
            password=password
        )

        if session[LoginType.EMAIL_IDENTITY]:
            yield handler.bind_emails(user_id, session["threepidCreds"])

        result = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        }
        self._remove_session(session)
        defer.returnValue(result)


def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.")
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.")


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)
