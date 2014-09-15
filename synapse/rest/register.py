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

import json
import urllib


class RegisterRestServlet(RestServlet):
    PATTERN = client_path_pattern("/register$")

    def on_GET(self, request):
        return (200, {
            "flows": [
                {
                    "type": LoginType.RECAPTCHA,
                    "stages": ([LoginType.RECAPTCHA, LoginType.EMAIL_IDENTITY,
                        LoginType.PASSWORD])
                },
                {
                    "type": LoginType.RECAPTCHA,
                    "stages": [LoginType.RECAPTCHA, LoginType.PASSWORD]
                },
            ]
        })

    @defer.inlineCallbacks
    def on_POST(self, request):
        register_json = _parse_json(request)

        session = (register_json["session"] if "session" in register_json
                  else None)
        try:
            login_type = register_json["type"]
            stages = {
                LoginType.RECAPTCHA: self._do_recaptcha,
                LoginType.PASSWORD: self._do_password,
                LoginType.EMAIL_IDENTITY: self._do_email_identity
            }

            session_info = None
            if session:
                session_info = self._get_session_info(session)

            response = yield stages[login_type](register_json, session_info)
            defer.returnValue((200, response))
        except KeyError:
            raise SynapseError(400, "Bad login type.")


        desired_user_id = None
        password = None

        if "password" in register_json:
            password = register_json["password"].encode("utf-8")

        if ("user_id" in register_json and
                type(register_json["user_id"]) == unicode):
            desired_user_id = register_json["user_id"].encode("utf-8")
            if urllib.quote(desired_user_id) != desired_user_id:
                raise SynapseError(
                    400,
                    "User ID must only contain characters which do not " +
                    "require URL encoding.")

        threepidCreds = None
        if 'threepidCreds' in register_json:
            threepidCreds = register_json['threepidCreds']

        captcha = {}
        if self.hs.config.enable_registration_captcha:
            challenge = None
            user_response = None
            try:
                captcha_type = register_json["captcha"]["type"]
                if captcha_type != "m.login.recaptcha":
                    raise SynapseError(400, "Sorry, only m.login.recaptcha " +
                                       "requests are supported.")
                challenge = register_json["captcha"]["challenge"]
                user_response = register_json["captcha"]["response"]
            except KeyError:
                raise SynapseError(400, "Captcha response is required",
                                   errcode=Codes.CAPTCHA_NEEDED)

            # TODO determine the source IP : May be an X-Forwarding-For header depending on config
            ip_addr = request.getClientIP()
            if self.hs.config.captcha_ip_origin_is_x_forwarded:
                # use the header
                if request.requestHeaders.hasHeader("X-Forwarded-For"):
                    ip_addr = request.requestHeaders.getRawHeaders(
                        "X-Forwarded-For")[0]

            captcha = {
                "ip": ip_addr,
                "private_key": self.hs.config.recaptcha_private_key,
                "challenge": challenge,
                "response": user_response
            }


        handler = self.handlers.registration_handler
        (user_id, token) = yield handler.register(
            localpart=desired_user_id,
            password=password,
            threepidCreds=threepidCreds,
            captcha_info=captcha)

        result = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        }
        defer.returnValue(
            (200, result)
        )

    def on_OPTIONS(self, request):
        return (200, {})

    def _get_session_info(self, session_id):
        pass

    def _do_recaptcha(self, register_json, session):
        pass

    def _do_email_identity(self, register_json, session):
        pass

    def _do_password(self, register_json, session):
        pass


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
