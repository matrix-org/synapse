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
from base import RestServlet, client_path_pattern

import json
import urllib


class RegisterRestServlet(RestServlet):
    PATTERN = client_path_pattern("/register$")

    @defer.inlineCallbacks
    def on_POST(self, request):
        desired_user_id = None
        password = None
        try:
            register_json = json.loads(request.content.read())
            if "password" in register_json:
                password = register_json["password"].encode("utf-8")

            if type(register_json["user_id"]) == unicode:
                desired_user_id = register_json["user_id"].encode("utf-8")
                if urllib.quote(desired_user_id) != desired_user_id:
                    raise SynapseError(
                        400,
                        "User ID must only contain characters which do not " +
                        "require URL encoding.")
        except ValueError:
            defer.returnValue((400, "No JSON object."))
        except KeyError:
            pass  # user_id is optional

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


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)
