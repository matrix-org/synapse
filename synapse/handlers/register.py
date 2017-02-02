# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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
import logging
import urllib

from twisted.internet import defer

from synapse.api.errors import (
    AuthError, Codes, SynapseError, RegistrationError, InvalidCaptchaError
)
from synapse.http.client import CaptchaServerHttpClient
from synapse.types import UserID
from synapse.util.async import run_on_reactor
from ._base import BaseHandler

logger = logging.getLogger(__name__)


class RegistrationHandler(BaseHandler):

    def __init__(self, hs):
        super(RegistrationHandler, self).__init__(hs)

        self.auth = hs.get_auth()
        self.captcha_client = CaptchaServerHttpClient(hs)

        self._next_generated_user_id = None

        self.macaroon_gen = hs.get_macaroon_generator()

    @defer.inlineCallbacks
    def check_username(self, localpart, guest_access_token=None,
                       assigned_user_id=None):
        yield run_on_reactor()

        if urllib.quote(localpart.encode('utf-8')) != localpart:
            raise SynapseError(
                400,
                "User ID can only contain characters a-z, 0-9, or '_-./'",
                Codes.INVALID_USERNAME
            )

        if localpart[0] == '_':
            raise SynapseError(
                400,
                "User ID may not begin with _",
                Codes.INVALID_USERNAME
            )

        user = UserID(localpart, self.hs.hostname)
        user_id = user.to_string()

        if assigned_user_id:
            if user_id == assigned_user_id:
                return
            else:
                raise SynapseError(
                    400,
                    "A different user ID has already been registered for this session",
                )

        yield self.check_user_id_not_appservice_exclusive(user_id)

        users = yield self.store.get_users_by_id_case_insensitive(user_id)
        if users:
            if not guest_access_token:
                raise SynapseError(
                    400,
                    "User ID already taken.",
                    errcode=Codes.USER_IN_USE,
                )
            user_data = yield self.auth.get_user_by_access_token(guest_access_token)
            if not user_data["is_guest"] or user_data["user"].localpart != localpart:
                raise AuthError(
                    403,
                    "Cannot register taken user ID without valid guest "
                    "credentials for that user.",
                    errcode=Codes.FORBIDDEN,
                )

    @defer.inlineCallbacks
    def register(
        self,
        localpart=None,
        password=None,
        generate_token=True,
        guest_access_token=None,
        make_guest=False,
        admin=False,
    ):
        """Registers a new client on the server.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be generated.
            password (str) : The password to assign to this user so they can
              login again. This can be None which means they cannot login again
              via a password (e.g. the user is an application service user).
            generate_token (bool): Whether a new access token should be
              generated. Having this be True should be considered deprecated,
              since it offers no means of associating a device_id with the
              access_token. Instead you should call auth_handler.issue_access_token
              after registration.
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
            yield self.check_username(localpart, guest_access_token=guest_access_token)

            was_guest = guest_access_token is not None

            if not was_guest:
                try:
                    int(localpart)
                    raise RegistrationError(
                        400,
                        "Numeric user IDs are reserved for guest users."
                    )
                except ValueError:
                    pass

            user = UserID(localpart, self.hs.hostname)
            user_id = user.to_string()

            token = None
            if generate_token:
                token = self.macaroon_gen.generate_access_token(user_id)
            yield self.store.register(
                user_id=user_id,
                token=token,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                create_profile_with_localpart=(
                    # If the user was a guest then they already have a profile
                    None if was_guest else user.localpart
                ),
                admin=admin,
            )
        else:
            # autogen a sequential user ID
            attempts = 0
            token = None
            user = None
            while not user:
                localpart = yield self._generate_user_id(attempts > 0)
                user = UserID(localpart, self.hs.hostname)
                user_id = user.to_string()
                yield self.check_user_id_not_appservice_exclusive(user_id)
                if generate_token:
                    token = self.macaroon_gen.generate_access_token(user_id)
                try:
                    yield self.store.register(
                        user_id=user_id,
                        token=token,
                        password_hash=password_hash,
                        make_guest=make_guest,
                        create_profile_with_localpart=user.localpart,
                    )
                except SynapseError:
                    # if user id is taken, just generate another
                    user = None
                    user_id = None
                    token = None
                    attempts += 1

        # We used to generate default identicons here, but nowadays
        # we want clients to generate their own as part of their branding
        # rather than there being consistent matrix-wide ones, so we don't.

        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def appservice_register(self, user_localpart, as_token):
        user = UserID(user_localpart, self.hs.hostname)
        user_id = user.to_string()
        service = self.store.get_app_service_by_token(as_token)
        if not service:
            raise AuthError(403, "Invalid application service token.")
        if not service.is_interested_in_user(user_id):
            raise SynapseError(
                400, "Invalid user localpart for this application service.",
                errcode=Codes.EXCLUSIVE
            )

        service_id = service.id if service.is_exclusive_user(user_id) else None

        yield self.check_user_id_not_appservice_exclusive(
            user_id, allowed_appservice=service
        )

        yield self.store.register(
            user_id=user_id,
            password_hash="",
            appservice_id=service_id,
            create_profile_with_localpart=user.localpart,
        )
        defer.returnValue(user_id)

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

        yield self.check_user_id_not_appservice_exclusive(user_id)
        token = self.macaroon_gen.generate_access_token(user_id)
        try:
            yield self.store.register(
                user_id=user_id,
                token=token,
                password_hash=None,
                create_profile_with_localpart=user.localpart,
            )
        except Exception as e:
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

    def check_user_id_not_appservice_exclusive(self, user_id, allowed_appservice=None):
        # valid user IDs must not clash with any user ID namespaces claimed by
        # application services.
        services = self.store.get_app_services()
        interested_services = [
            s for s in services
            if s.is_interested_in_user(user_id)
            and s != allowed_appservice
        ]
        for service in interested_services:
            if service.is_exclusive_user(user_id):
                raise SynapseError(
                    400, "This user ID is reserved by an application service.",
                    errcode=Codes.EXCLUSIVE
                )

    @defer.inlineCallbacks
    def _generate_user_id(self, reseed=False):
        if reseed or self._next_generated_user_id is None:
            self._next_generated_user_id = (
                yield self.store.find_next_generated_user_id_localpart()
            )

        id = self._next_generated_user_id
        self._next_generated_user_id += 1
        defer.returnValue(str(id))

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

    @defer.inlineCallbacks
    def get_or_create_user(self, requester, localpart, displayname,
                           password_hash=None):
        """Creates a new user if the user does not exist,
        else revokes all previous access tokens and generates a new one.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be randomly generated.
        Returns:
            A tuple of (user_id, access_token).
        Raises:
            RegistrationError if there was a problem registering.
        """
        yield run_on_reactor()

        if localpart is None:
            raise SynapseError(400, "Request must include user id")

        need_register = True

        try:
            yield self.check_username(localpart)
        except SynapseError as e:
            if e.errcode == Codes.USER_IN_USE:
                need_register = False
            else:
                raise

        user = UserID(localpart, self.hs.hostname)
        user_id = user.to_string()
        token = self.macaroon_gen.generate_access_token(user_id)

        if need_register:
            yield self.store.register(
                user_id=user_id,
                token=token,
                password_hash=password_hash,
                create_profile_with_localpart=user.localpart,
            )
        else:
            yield self.store.user_delete_access_tokens(user_id=user_id)
            yield self.store.add_access_token_to_user(user_id=user_id, token=token)

        if displayname is not None:
            logger.info("setting user display name: %s -> %s", user_id, displayname)
            profile_handler = self.hs.get_handlers().profile_handler
            yield profile_handler.set_displayname(
                user, requester, displayname, by_admin=True,
            )

        defer.returnValue((user_id, token))

    def auth_handler(self):
        return self.hs.get_auth_handler()

    @defer.inlineCallbacks
    def guest_access_token_for(self, medium, address, inviter_user_id):
        access_token = yield self.store.get_3pid_guest_access_token(medium, address)
        if access_token:
            defer.returnValue(access_token)

        _, access_token = yield self.register(
            generate_token=True,
            make_guest=True
        )
        access_token = yield self.store.save_or_get_3pid_guest_access_token(
            medium, address, access_token, inviter_user_id
        )
        defer.returnValue(access_token)
