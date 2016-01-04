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
    AuthError, Codes, SynapseError, RegistrationError, InvalidCaptchaError
)
from ._base import BaseHandler
import synapse.util.stringutils as stringutils
from synapse.util.async import run_on_reactor
from synapse.http.client import CaptchaServerHttpClient

import logging
import urllib

logger = logging.getLogger(__name__)


def registered_user(distributor, user):
    return distributor.fire("registered_user", user)


class RegistrationHandler(BaseHandler):

    def __init__(self, hs):
        super(RegistrationHandler, self).__init__(hs)

        self.distributor = hs.get_distributor()
        self.distributor.declare("registered_user")
        self.captcha_client = CaptchaServerHttpClient(hs)

    @defer.inlineCallbacks
    def check_username(self, localpart):
        yield run_on_reactor()

        if urllib.quote(localpart) != localpart:
            raise SynapseError(
                400,
                "User ID must only contain characters which do not"
                " require URL encoding."
            )

        user = UserID(localpart, self.hs.hostname)
        user_id = user.to_string()

        yield self.check_user_id_is_valid(user_id)

        users = yield self.store.get_users_by_id_case_insensitive(user_id)
        if users:
            raise SynapseError(
                400,
                "User ID already taken.",
                errcode=Codes.USER_IN_USE,
            )

    @defer.inlineCallbacks
    def register(self, localpart=None, password=None, generate_token=True):
        """Registers a new client on the server.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be randomly generated.
            password (str) : The password to assign to this user so they can
            login again. This can be None which means they cannot login again
            via a password (e.g. the user is an application service user).
        Returns:
            A tuple of (user_id, access_token).
        Raises:
            RegistrationError if there was a problem registering.
        """
        yield run_on_reactor()
        password_hash = None
        if password:
            password_hash = self.auth_handler().hash(password)

        if localpart:
            yield self.check_username(localpart)

            user = UserID(localpart, self.hs.hostname)
            user_id = user.to_string()

            token = None
            if generate_token:
                token = self.auth_handler().generate_access_token(user_id)
            yield self.store.register(
                user_id=user_id,
                token=token,
                password_hash=password_hash
            )

            yield registered_user(self.distributor, user)
        else:
            # autogen a random user ID
            attempts = 0
            user_id = None
            token = None
            while not user_id:
                try:
                    localpart = self._generate_user_id()
                    user = UserID(localpart, self.hs.hostname)
                    user_id = user.to_string()
                    yield self.check_user_id_is_valid(user_id)
                    if generate_token:
                        token = self.auth_handler().generate_access_token(user_id)
                    yield self.store.register(
                        user_id=user_id,
                        token=token,
                        password_hash=password_hash)

                    yield registered_user(self.distributor, user)
                except SynapseError:
                    # if user id is taken, just generate another
                    user_id = None
                    token = None
                    attempts += 1
                    if attempts > 5:
                        raise RegistrationError(
                            500, "Cannot generate user ID.")

        # We used to generate default identicons here, but nowadays
        # we want clients to generate their own as part of their branding
        # rather than there being consistent matrix-wide ones, so we don't.

        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def appservice_register(self, user_localpart, as_token):
        user = UserID(user_localpart, self.hs.hostname)
        user_id = user.to_string()
        service = yield self.store.get_app_service_by_token(as_token)
        if not service:
            raise AuthError(403, "Invalid application service token.")
        if not service.is_interested_in_user(user_id):
            raise SynapseError(
                400, "Invalid user localpart for this application service.",
                errcode=Codes.EXCLUSIVE
            )
        token = self.auth_handler().generate_access_token(user_id)
        yield self.store.register(
            user_id=user_id,
            token=token,
            password_hash=""
        )
        registered_user(self.distributor, user)
        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def check_recaptcha(self, ip, private_key, challenge, response):
        """
        Checks a recaptcha is correct.

        Used only by c/s api v1
        """

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
    def register_saml2(self, localpart):
        """
        Registers email_id as SAML2 Based Auth.
        """
        if urllib.quote(localpart) != localpart:
            raise SynapseError(
                400,
                "User ID must only contain characters which do not"
                " require URL encoding."
                )
        user = UserID(localpart, self.hs.hostname)
        user_id = user.to_string()

        yield self.check_user_id_is_valid(user_id)
        token = self.auth_handler().generate_access_token(user_id)
        try:
            yield self.store.register(
                user_id=user_id,
                token=token,
                password_hash=None
            )
            yield registered_user(self.distributor, user)
        except Exception, e:
            yield self.store.add_access_token_to_user(user_id, token)
            # Ignore Registration errors
            logger.exception(e)
        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def register_email(self, threepidCreds):
        """
        Registers emails with an identity server.

        Used only by c/s api v1
        """

        for c in threepidCreds:
            logger.info("validating theeepidcred sid %s on id server %s",
                        c['sid'], c['idServer'])
            try:
                identity_handler = self.hs.get_handlers().identity_handler
                threepid = yield identity_handler.threepid_from_creds(c)
            except:
                logger.exception("Couldn't validate 3pid")
                raise RegistrationError(400, "Couldn't validate 3pid")

            if not threepid:
                raise RegistrationError(400, "Couldn't validate 3pid")
            logger.info("got threepid with medium '%s' and address '%s'",
                        threepid['medium'], threepid['address'])

    @defer.inlineCallbacks
    def bind_emails(self, user_id, threepidCreds):
        """Links emails with a user ID and informs an identity server.

        Used only by c/s api v1
        """

        # Now we have a matrix ID, bind it to the threepids we were given
        for c in threepidCreds:
            identity_handler = self.hs.get_handlers().identity_handler
            # XXX: This should be a deferred list, shouldn't it?
            yield identity_handler.bind_threepid(c, user_id)

    @defer.inlineCallbacks
    def check_user_id_is_valid(self, user_id):
        # valid user IDs must not clash with any user ID namespaces claimed by
        # application services.
        services = yield self.store.get_app_services()
        interested_services = [
            s for s in services if s.is_interested_in_user(user_id)
        ]
        for service in interested_services:
            if service.is_exclusive_user(user_id):
                raise SynapseError(
                    400, "This user ID is reserved by an application service.",
                    errcode=Codes.EXCLUSIVE
                )

    def _generate_user_id(self):
        return "-" + stringutils.random_string(18)

    @defer.inlineCallbacks
    def _validate_captcha(self, ip_addr, private_key, challenge, response):
        """Validates the captcha provided.

        Used only by c/s api v1

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
        """
        Used only by c/s api v1
        """
        data = yield self.captcha_client.post_urlencoded_get_raw(
            "http://www.google.com:80/recaptcha/api/verify",
            args={
                'privatekey': private_key,
                'remoteip': ip_addr,
                'challenge': challenge,
                'response': response
            }
        )
        defer.returnValue(data)

    def auth_handler(self):
        return self.hs.get_handlers().auth_handler
