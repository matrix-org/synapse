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

"""Contains functions for registering clients."""
from twisted.internet import defer

from synapse.types import UserID
from synapse.api.errors import (
    SynapseError, RegistrationError, InvalidCaptchaError, CodeMessageException
)
from ._base import BaseHandler
import synapse.util.stringutils as stringutils
from synapse.util.async import run_on_reactor
from synapse.http.client import SimpleHttpClient
from synapse.http.client import CaptchaServerHttpClient

import base64
import bcrypt
import json
import logging

logger = logging.getLogger(__name__)


class RegistrationHandler(BaseHandler):

    def __init__(self, hs):
        super(RegistrationHandler, self).__init__(hs)

        self.distributor = hs.get_distributor()
        self.distributor.declare("registered_user")

    @defer.inlineCallbacks
    def register(self, localpart=None, password=None):
        """Registers a new client on the server.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be randomly generated.
            password (str) : The password to assign to this user so they can
            login again.
        Returns:
            A tuple of (user_id, access_token).
        Raises:
            RegistrationError if there was a problem registering.
        """
        yield run_on_reactor()
        password_hash = None
        if password:
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt())

        if localpart:
            user = UserID(localpart, self.hs.hostname)
            user_id = user.to_string()

            token = self._generate_token(user_id)
            yield self.store.register(
                user_id=user_id,
                token=token,
                password_hash=password_hash
            )

            yield self.distributor.fire("registered_user", user)
        else:
            # autogen a random user ID
            attempts = 0
            user_id = None
            token = None
            while not user_id and not token:
                try:
                    localpart = self._generate_user_id()
                    user = UserID(localpart, self.hs.hostname)
                    user_id = user.to_string()

                    token = self._generate_token(user_id)
                    yield self.store.register(
                        user_id=user_id,
                        token=token,
                        password_hash=password_hash)

                    self.distributor.fire("registered_user", user)
                except SynapseError:
                    # if user id is taken, just generate another
                    user_id = None
                    token = None
                    attempts += 1
                    if attempts > 5:
                        raise RegistrationError(
                            500, "Cannot generate user ID.")

        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def check_recaptcha(self, ip, private_key, challenge, response):
        """Checks a recaptcha is correct."""

        captcha_response = yield self._validate_captcha(
            ip,
            private_key,
            challenge,
            response
        )
        if not captcha_response["valid"]:
            logger.info("Invalid captcha entered from %s. Error: %s",
                        ip, captcha_response["error_url"])
            raise InvalidCaptchaError(
                error_url=captcha_response["error_url"]
            )
        else:
            logger.info("Valid captcha entered from %s", ip)

    @defer.inlineCallbacks
    def register_email(self, threepidCreds):
        """Registers emails with an identity server."""

        for c in threepidCreds:
            logger.info("validating theeepidcred sid %s on id server %s",
                        c['sid'], c['idServer'])
            try:
                threepid = yield self._threepid_from_creds(c)
            except:
                logger.exception("Couldn't validate 3pid")
                raise RegistrationError(400, "Couldn't validate 3pid")

            if not threepid:
                raise RegistrationError(400, "Couldn't validate 3pid")
            logger.info("got threepid with medium '%s' and address '%s'",
                        threepid['medium'], threepid['address'])

    @defer.inlineCallbacks
    def bind_emails(self, user_id, threepidCreds):
        """Links emails with a user ID and informs an identity server."""

        # Now we have a matrix ID, bind it to the threepids we were given
        for c in threepidCreds:
            # XXX: This should be a deferred list, shouldn't it?
            yield self._bind_threepid(c, user_id)

    def _generate_token(self, user_id):
        # urlsafe variant uses _ and - so use . as the separator and replace
        # all =s with .s so http clients don't quote =s when it is used as
        # query params.
        return (base64.urlsafe_b64encode(user_id).replace('=', '.') + '.' +
                stringutils.random_string(18))

    def _generate_user_id(self):
        return "-" + stringutils.random_string(18)

    @defer.inlineCallbacks
    def _threepid_from_creds(self, creds):
        # TODO: get this from the homeserver rather than creating a new one for
        # each request
        http_client = SimpleHttpClient(self.hs)
        # XXX: make this configurable!
        trustedIdServers = ['matrix.org:8090', 'matrix.org']
        if not creds['idServer'] in trustedIdServers:
            logger.warn('%s is not a trusted ID server: rejecting 3pid ' +
                        'credentials', creds['idServer'])
            defer.returnValue(None)

        data = {}
        try:
            data = yield http_client.get_json(
                # XXX: This should be HTTPS
                "http://%s%s" % (
                    creds['idServer'],
                    "/_matrix/identity/api/v1/3pid/getValidated3pid"
                ),
                {'sid': creds['sid'], 'clientSecret': creds['clientSecret']}
            )
        except CodeMessageException as e:
            data = json.loads(e.msg)

        if 'medium' in data:
            defer.returnValue(data)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _bind_threepid(self, creds, mxid):
        yield
        logger.debug("binding threepid")
        http_client = SimpleHttpClient(self.hs)
        data = None
        try:
            data = yield http_client.post_urlencoded_get_json(
                # XXX: Change when ID servers are all HTTPS
                "http://%s%s" % (
                    creds['idServer'], "/_matrix/identity/api/v1/3pid/bind"
                ),
                {
                    'sid': creds['sid'],
                    'clientSecret': creds['clientSecret'],
                    'mxid': mxid,
                }
            )
            logger.debug("bound threepid")
        except CodeMessageException as e:
            data = json.loads(e.msg)
        defer.returnValue(data)

    @defer.inlineCallbacks
    def _validate_captcha(self, ip_addr, private_key, challenge, response):
        """Validates the captcha provided.

        Returns:
            dict: Containing 'valid'(bool) and 'error_url'(str) if invalid.

        """
        response = yield self._submit_captcha(ip_addr, private_key, challenge,
                                              response)
        # parse Google's response. Lovely format..
        lines = response.split('\n')
        json = {
            "valid": lines[0] == 'true',
            "error_url": "http://www.google.com/recaptcha/api/challenge?" +
                         "error=%s" % lines[1]
        }
        defer.returnValue(json)

    @defer.inlineCallbacks
    def _submit_captcha(self, ip_addr, private_key, challenge, response):
        # TODO: get this from the homeserver rather than creating a new one for
        # each request
        client = CaptchaServerHttpClient(self.hs)
        data = yield client.post_urlencoded_get_raw(
            "http://www.google.com:80/recaptcha/api/verify",
            args={
                'privatekey': private_key,
                'remoteip': ip_addr,
                'challenge': challenge,
                'response': response
            }
        )
        defer.returnValue(data)
