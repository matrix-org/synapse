# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.types import UserID
from base import ClientV1RestServlet, client_path_pattern

import simplejson as json
import urllib

import logging
from saml2 import BINDING_HTTP_POST
from saml2 import config
from saml2.client import Saml2Client


logger = logging.getLogger(__name__)


class LoginRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login$")
    PASS_TYPE = "m.login.password"
    SAML2_TYPE = "m.login.saml2"

    def __init__(self, hs):
        super(LoginRestServlet, self).__init__(hs)
        self.idp_redirect_url = hs.config.saml2_config['idp_redirect_url']
        self.saml2_enabled = hs.config.saml2_config['enabled']

    def on_GET(self, request):
        flows = [{"type": LoginRestServlet.PASS_TYPE}]
        if self.saml2_enabled:
            flows.append({"type": LoginRestServlet.SAML2_TYPE})
        return (200, {"flows": flows})

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        login_submission = _parse_json(request)
        try:
            if login_submission["type"] == LoginRestServlet.PASS_TYPE:
                result = yield self.do_password_login(login_submission)
                defer.returnValue(result)
            elif self.saml2_enabled and (login_submission["type"] ==
                                         LoginRestServlet.SAML2_TYPE):
                relay_state = ""
                if "relay_state" in login_submission:
                    relay_state = "&RelayState="+urllib.quote(
                                  login_submission["relay_state"])
                result = {
                    "uri": "%s%s" % (self.idp_redirect_url, relay_state)
                }
                defer.returnValue((200, result))
            else:
                raise SynapseError(400, "Bad login type.")
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

    @defer.inlineCallbacks
    def do_password_login(self, login_submission):
        if not login_submission["user"].startswith('@'):
            login_submission["user"] = UserID.create(
                login_submission["user"], self.hs.hostname).to_string()

        handler = self.handlers.login_handler
        token = yield handler.login(
            user=login_submission["user"],
            password=login_submission["password"])

        result = {
            "user_id": login_submission["user"],  # may have changed
            "access_token": token,
            "home_server": self.hs.hostname,
        }

        defer.returnValue((200, result))


class LoginFallbackRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login/fallback$")

    def on_GET(self, request):
        # TODO(kegan): This should be returning some HTML which is capable of
        # hitting LoginRestServlet
        return (200, {})


class PasswordResetRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login/reset")

    @defer.inlineCallbacks
    def on_POST(self, request):
        reset_info = _parse_json(request)
        try:
            email = reset_info["email"]
            user_id = reset_info["user_id"]
            handler = self.handlers.login_handler
            yield handler.reset_password(user_id, email)
            # purposefully give no feedback to avoid people hammering different
            # combinations.
            defer.returnValue((200, {}))
        except KeyError:
            raise SynapseError(
                400,
                "Missing keys. Requires 'email' and 'user_id'."
            )


class SAML2RestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login/saml2")

    def __init__(self, hs):
        super(SAML2RestServlet, self).__init__(hs)
        self.sp_config = hs.config.saml2_config['config_path']

    @defer.inlineCallbacks
    def on_POST(self, request):
        saml2_auth = None
        try:
            conf = config.SPConfig()
            conf.load_file(self.sp_config)
            SP = Saml2Client(conf)
            saml2_auth = SP.parse_authn_request_response(
                request.args['SAMLResponse'][0], BINDING_HTTP_POST)
        except Exception, e:        # Not authenticated
            logger.exception(e)
        if saml2_auth and saml2_auth.status_ok() and not saml2_auth.not_signed:
            username = saml2_auth.name_id.text
            handler = self.handlers.registration_handler
            (user_id, token) = yield handler.register_saml2(username)
            # Forward to the RelayState callback along with ava
            if 'RelayState' in request.args:
                request.redirect(urllib.unquote(
                                 request.args['RelayState'][0]) +
                                 '?status=authenticated&access_token=' +
                                 token + '&user_id=' + user_id + '&ava=' +
                                 urllib.quote(json.dumps(saml2_auth.ava)))
                request.finish()
                defer.returnValue(None)
            defer.returnValue((200, {"status": "authenticated",
                                     "user_id": user_id, "token": token,
                                     "ava": saml2_auth.ava}))
        elif 'RelayState' in request.args:
            request.redirect(urllib.unquote(
                             request.args['RelayState'][0]) +
                             '?status=not_authenticated')
            request.finish()
            defer.returnValue(None)
        defer.returnValue((200, {"status": "not_authenticated"}))


def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.")
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.")


def register_servlets(hs, http_server):
    LoginRestServlet(hs).register(http_server)
    if hs.config.saml2_config['enabled']:
        SAML2RestServlet(hs).register(http_server)
    # TODO PasswordResetRestServlet(hs).register(http_server)
