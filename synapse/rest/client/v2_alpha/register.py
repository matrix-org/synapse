# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.api.constants import LoginType
from synapse.api.errors import SynapseError, Codes
from synapse.http.servlet import RestServlet

from ._base import client_v2_pattern, parse_request_allow_empty

import logging
import hmac
from hashlib import sha1
from synapse.util.async import run_on_reactor


# We ought to be using hmac.compare_digest() but on older pythons it doesn't
# exist. It's a _really minor_ security flaw to use plain string comparison
# because the timing attack is so obscured by all the other code here it's
# unlikely to make much difference
if hasattr(hmac, "compare_digest"):
    compare_digest = hmac.compare_digest
else:
    compare_digest = lambda a, b: a == b


logger = logging.getLogger(__name__)


class RegisterRestServlet(RestServlet):
    PATTERN = client_v2_pattern("/register")

    def __init__(self, hs):
        super(RegisterRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_handlers().auth_handler
        self.registration_handler = hs.get_handlers().registration_handler
        self.identity_handler = hs.get_handlers().identity_handler
        self.login_handler = hs.get_handlers().login_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        yield run_on_reactor()

        body = parse_request_allow_empty(request)
        # we do basic sanity checks here because the auth
        # layer will store these in sessions
        if 'password' in body:
            if ((not isinstance(body['password'], str) and
                    not isinstance(body['password'], unicode)) or
                    len(body['password']) > 512):
                raise SynapseError(400, "Invalid password")

        if 'username' in body:
            if ((not isinstance(body['username'], str) and
                    not isinstance(body['username'], unicode)) or
                    len(body['username']) > 512):
                raise SynapseError(400, "Invalid username")
            desired_username = body['username']
            yield self.registration_handler.check_username(desired_username)

        is_using_shared_secret = False
        is_application_server = False

        service = None
        if 'access_token' in request.args:
            service = yield self.auth.get_appservice_by_req(request)

        if self.hs.config.enable_registration_captcha:
            flows = [
                [LoginType.RECAPTCHA],
                [LoginType.EMAIL_IDENTITY, LoginType.RECAPTCHA]
            ]
        else:
            flows = [
                [LoginType.DUMMY],
                [LoginType.EMAIL_IDENTITY]
            ]

        result = None
        if service:
            is_application_server = True
            params = body
        elif 'mac' in body:
            # Check registration-specific shared secret auth
            if 'username' not in body:
                raise SynapseError(400, "", Codes.MISSING_PARAM)
            self._check_shared_secret_auth(
                body['username'], body['mac']
            )
            is_using_shared_secret = True
            params = body
        else:
            authed, result, params = yield self.auth_handler.check_auth(
                flows, body, self.hs.get_ip_from_request(request)
            )

            if not authed:
                defer.returnValue((401, result))

        can_register = (
            not self.hs.config.disable_registration
            or is_application_server
            or is_using_shared_secret
        )
        if not can_register:
            raise SynapseError(403, "Registration has been disabled")

        if 'password' not in params:
            raise SynapseError(400, "", Codes.MISSING_PARAM)
        desired_username = params['username'] if 'username' in params else None
        new_password = params['password']

        (user_id, token) = yield self.registration_handler.register(
            localpart=desired_username,
            password=new_password
        )

        if result and LoginType.EMAIL_IDENTITY in result:
            threepid = result[LoginType.EMAIL_IDENTITY]

            for reqd in ['medium', 'address', 'validated_at']:
                if reqd not in threepid:
                    logger.info("Can't add incomplete 3pid")
                else:
                    yield self.login_handler.add_threepid(
                        user_id,
                        threepid['medium'],
                        threepid['address'],
                        threepid['validated_at'],
                    )

            if 'bind_email' in params and params['bind_email']:
                logger.info("bind_email specified: binding")

                emailThreepid = result[LoginType.EMAIL_IDENTITY]
                threepid_creds = emailThreepid['threepid_creds']
                logger.debug("Binding emails %s to %s" % (
                    emailThreepid, user_id
                ))
                yield self.identity_handler.bind_threepid(threepid_creds, user_id)
            else:
                logger.info("bind_email not specified: not binding email")

        result = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        }

        defer.returnValue((200, result))

    def on_OPTIONS(self, _):
        return 200, {}

    def _check_shared_secret_auth(self, username, mac):
        if not self.hs.config.registration_shared_secret:
            raise SynapseError(400, "Shared secret registration is not enabled")

        user = username.encode("utf-8")

        # str() because otherwise hmac complains that 'unicode' does not
        # have the buffer interface
        got_mac = str(mac)

        want_mac = hmac.new(
            key=self.hs.config.registration_shared_secret,
            msg=user,
            digestmod=sha1,
        ).hexdigest()

        if compare_digest(want_mac, got_mac):
            return True
        else:
            raise SynapseError(
                403, "HMAC incorrect",
            )


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)
