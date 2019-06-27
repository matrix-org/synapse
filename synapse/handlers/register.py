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

from twisted.internet import defer

from synapse import types
from synapse.api.constants import MAX_USERID_LENGTH, LoginType
from synapse.api.errors import (
    AuthError,
    Codes,
    ConsentNotGivenError,
    InvalidCaptchaError,
    LimitExceededError,
    RegistrationError,
    SynapseError,
)
from synapse.config.server import is_threepid_reserved
from synapse.http.client import CaptchaServerHttpClient
from synapse.http.servlet import assert_params_in_dict
from synapse.replication.http.login import RegisterDeviceReplicationServlet
from synapse.replication.http.register import (
    ReplicationPostRegisterActionsServlet,
    ReplicationRegisterServlet,
)
from synapse.types import RoomAlias, RoomID, UserID, create_requester
from synapse.util.async_helpers import Linearizer
from synapse.util.threepids import check_3pid_allowed

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class RegistrationHandler(BaseHandler):
    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer):
        """
        super(RegistrationHandler, self).__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self.profile_handler = hs.get_profile_handler()
        self.user_directory_handler = hs.get_user_directory_handler()
        self.captcha_client = CaptchaServerHttpClient(hs)
        self.identity_handler = self.hs.get_handlers().identity_handler
        self.ratelimiter = hs.get_registration_ratelimiter()

        self._next_generated_user_id = None

        self.macaroon_gen = hs.get_macaroon_generator()

        self._generate_user_id_linearizer = Linearizer(
            name="_generate_user_id_linearizer"
        )
        self._server_notices_mxid = hs.config.server_notices_mxid

        if hs.config.worker_app:
            self._register_client = ReplicationRegisterServlet.make_client(hs)
            self._register_device_client = RegisterDeviceReplicationServlet.make_client(
                hs
            )
            self._post_registration_client = ReplicationPostRegisterActionsServlet.make_client(
                hs
            )
        else:
            self.device_handler = hs.get_device_handler()
            self.pusher_pool = hs.get_pusherpool()

    @defer.inlineCallbacks
    def check_username(self, localpart, guest_access_token=None, assigned_user_id=None):
        if types.contains_invalid_mxid_characters(localpart):
            raise SynapseError(
                400,
                "User ID can only contain characters a-z, 0-9, or '=_-./'",
                Codes.INVALID_USERNAME,
            )

        if not localpart:
            raise SynapseError(400, "User ID cannot be empty", Codes.INVALID_USERNAME)

        if localpart[0] == "_":
            raise SynapseError(
                400, "User ID may not begin with _", Codes.INVALID_USERNAME
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

        self.check_user_id_not_appservice_exclusive(user_id)

        if len(user_id) > MAX_USERID_LENGTH:
            raise SynapseError(
                400,
                "User ID may not be longer than %s characters" % (MAX_USERID_LENGTH,),
                Codes.INVALID_USERNAME,
            )

        users = yield self.store.get_users_by_id_case_insensitive(user_id)
        if users:
            if not guest_access_token:
                raise SynapseError(
                    400, "User ID already taken.", errcode=Codes.USER_IN_USE
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
        threepid=None,
        user_type=None,
        default_display_name=None,
        address=None,
        bind_emails=[],
    ):
        """Registers a new client on the server.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be generated.
            password (unicode) : The password to assign to this user so they can
              login again. This can be None which means they cannot login again
              via a password (e.g. the user is an application service user).
            generate_token (bool): Whether a new access token should be
              generated. Having this be True should be considered deprecated,
              since it offers no means of associating a device_id with the
              access_token. Instead you should call auth_handler.issue_access_token
              after registration.
            user_type (str|None): type of user. One of the values from
              api.constants.UserTypes, or None for a normal user.
            default_display_name (unicode|None): if set, the new user's displayname
              will be set to this. Defaults to 'localpart'.
            address (str|None): the IP address used to perform the registration.
            bind_emails (List[str]): list of emails to bind to this account.
        Returns:
            A tuple of (user_id, access_token).
        Raises:
            RegistrationError if there was a problem registering.
        """

        yield self.auth.check_auth_blocking(threepid=threepid)
        password_hash = None
        if password:
            password_hash = yield self._auth_handler.hash(password)

        if localpart:
            yield self.check_username(localpart, guest_access_token=guest_access_token)

            was_guest = guest_access_token is not None

            if not was_guest:
                try:
                    int(localpart)
                    raise RegistrationError(
                        400, "Numeric user IDs are reserved for guest users."
                    )
                except ValueError:
                    pass

            user = UserID(localpart, self.hs.hostname)
            user_id = user.to_string()

            if was_guest:
                # If the user was a guest then they already have a profile
                default_display_name = None

            elif default_display_name is None:
                default_display_name = localpart

            token = None
            if generate_token:
                token = self.macaroon_gen.generate_access_token(user_id)
            yield self.register_with_store(
                user_id=user_id,
                token=token,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                create_profile_with_displayname=default_display_name,
                admin=admin,
                user_type=user_type,
                address=address,
            )

            if self.hs.config.user_directory_search_all_users:
                profile = yield self.store.get_profileinfo(localpart)
                yield self.user_directory_handler.handle_local_profile_change(
                    user_id, profile
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
                if default_display_name is None:
                    default_display_name = localpart
                try:
                    yield self.register_with_store(
                        user_id=user_id,
                        token=token,
                        password_hash=password_hash,
                        make_guest=make_guest,
                        create_profile_with_displayname=default_display_name,
                        address=address,
                    )
                except SynapseError:
                    # if user id is taken, just generate another
                    user = None
                    user_id = None
                    token = None
                    attempts += 1
        if not self.hs.config.user_consent_at_registration:
            yield self._auto_join_rooms(user_id)

        # Bind any specified emails to this account
        current_time = self.hs.get_clock().time_msec()
        for email in bind_emails:
            # generate threepid dict
            threepid_dict = {
                "medium": "email",
                "address": email,
                "validated_at": current_time,
            }

            # Bind email to new account
            yield self._register_email_threepid(user_id, threepid_dict, None, False)

        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def _auto_join_rooms(self, user_id):
        """Automatically joins users to auto join rooms - creating the room in the first place
        if the user is the first to be created.

        Args:
            user_id(str): The user to join
        """
        # auto-join the user to any rooms we're supposed to dump them into
        fake_requester = create_requester(user_id)

        # try to create the room if we're the first real user on the server. Note
        # that an auto-generated support user is not a real user and will never be
        # the user to create the room
        should_auto_create_rooms = False
        is_support = yield self.store.is_support_user(user_id)
        # There is an edge case where the first user is the support user, then
        # the room is never created, though this seems unlikely and
        # recoverable from given the support user being involved in the first
        # place.
        if self.hs.config.autocreate_auto_join_rooms and not is_support:
            count = yield self.store.count_all_users()
            should_auto_create_rooms = count == 1
        for r in self.hs.config.auto_join_rooms:
            try:
                if should_auto_create_rooms:
                    room_alias = RoomAlias.from_string(r)
                    if self.hs.hostname != room_alias.domain:
                        logger.warning(
                            "Cannot create room alias %s, "
                            "it does not match server domain",
                            r,
                        )
                    else:
                        # create room expects the localpart of the room alias
                        room_alias_localpart = room_alias.localpart

                        # getting the RoomCreationHandler during init gives a dependency
                        # loop
                        yield self.hs.get_room_creation_handler().create_room(
                            fake_requester,
                            config={
                                "preset": "public_chat",
                                "room_alias_name": room_alias_localpart,
                            },
                            ratelimit=False,
                        )
                else:
                    yield self._join_user_to_room(fake_requester, r)
            except ConsentNotGivenError as e:
                # Technically not necessary to pull out this error though
                # moving away from bare excepts is a good thing to do.
                logger.error("Failed to join new user to %r: %r", r, e)
            except Exception as e:
                logger.error("Failed to join new user to %r: %r", r, e)

    @defer.inlineCallbacks
    def post_consent_actions(self, user_id):
        """A series of registration actions that can only be carried out once consent
        has been granted

        Args:
            user_id (str): The user to join
        """
        yield self._auto_join_rooms(user_id)

    @defer.inlineCallbacks
    def appservice_register(self, user_localpart, as_token):
        user = UserID(user_localpart, self.hs.hostname)
        user_id = user.to_string()
        service = self.store.get_app_service_by_token(as_token)
        if not service:
            raise AuthError(403, "Invalid application service token.")
        if not service.is_interested_in_user(user_id):
            raise SynapseError(
                400,
                "Invalid user localpart for this application service.",
                errcode=Codes.EXCLUSIVE,
            )

        service_id = service.id if service.is_exclusive_user(user_id) else None

        yield self.check_user_id_not_appservice_exclusive(
            user_id, allowed_appservice=service
        )

        yield self.register_with_store(
            user_id=user_id,
            password_hash="",
            appservice_id=service_id,
            create_profile_with_displayname=user.localpart,
        )
        defer.returnValue(user_id)

    @defer.inlineCallbacks
    def check_recaptcha(self, ip, private_key, challenge, response):
        """
        Checks a recaptcha is correct.

        Used only by c/s api v1
        """

        captcha_response = yield self._validate_captcha(
            ip, private_key, challenge, response
        )
        if not captcha_response["valid"]:
            logger.info(
                "Invalid captcha entered from %s. Error: %s",
                ip,
                captcha_response["error_url"],
            )
            raise InvalidCaptchaError(error_url=captcha_response["error_url"])
        else:
            logger.info("Valid captcha entered from %s", ip)

    @defer.inlineCallbacks
    def register_email(self, threepidCreds):
        """
        Registers emails with an identity server.

        Used only by c/s api v1
        """

        for c in threepidCreds:
            logger.info(
                "validating threepidcred sid %s on id server %s",
                c["sid"],
                c["idServer"],
            )
            try:
                threepid = yield self.identity_handler.threepid_from_creds(c)
            except Exception:
                logger.exception("Couldn't validate 3pid")
                raise RegistrationError(400, "Couldn't validate 3pid")

            if not threepid:
                raise RegistrationError(400, "Couldn't validate 3pid")
            logger.info(
                "got threepid with medium '%s' and address '%s'",
                threepid["medium"],
                threepid["address"],
            )

            if not check_3pid_allowed(self.hs, threepid["medium"], threepid["address"]):
                raise RegistrationError(403, "Third party identifier is not allowed")

    @defer.inlineCallbacks
    def bind_emails(self, user_id, threepidCreds):
        """Links emails with a user ID and informs an identity server.

        Used only by c/s api v1
        """

        # Now we have a matrix ID, bind it to the threepids we were given
        for c in threepidCreds:
            # XXX: This should be a deferred list, shouldn't it?
            yield self.identity_handler.bind_threepid(c, user_id)

    def check_user_id_not_appservice_exclusive(self, user_id, allowed_appservice=None):
        # don't allow people to register the server notices mxid
        if self._server_notices_mxid is not None:
            if user_id == self._server_notices_mxid:
                raise SynapseError(
                    400, "This user ID is reserved.", errcode=Codes.EXCLUSIVE
                )

        # valid user IDs must not clash with any user ID namespaces claimed by
        # application services.
        services = self.store.get_app_services()
        interested_services = [
            s
            for s in services
            if s.is_interested_in_user(user_id) and s != allowed_appservice
        ]
        for service in interested_services:
            if service.is_exclusive_user(user_id):
                raise SynapseError(
                    400,
                    "This user ID is reserved by an application service.",
                    errcode=Codes.EXCLUSIVE,
                )

    @defer.inlineCallbacks
    def _generate_user_id(self, reseed=False):
        if reseed or self._next_generated_user_id is None:
            with (yield self._generate_user_id_linearizer.queue(())):
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
        response = yield self._submit_captcha(ip_addr, private_key, challenge, response)
        # parse Google's response. Lovely format..
        lines = response.split("\n")
        json = {
            "valid": lines[0] == "true",
            "error_url": "http://www.recaptcha.net/recaptcha/api/challenge?"
            + "error=%s" % lines[1],
        }
        defer.returnValue(json)

    @defer.inlineCallbacks
    def _submit_captcha(self, ip_addr, private_key, challenge, response):
        """
        Used only by c/s api v1
        """
        data = yield self.captcha_client.post_urlencoded_get_raw(
            "http://www.recaptcha.net:80/recaptcha/api/verify",
            args={
                "privatekey": private_key,
                "remoteip": ip_addr,
                "challenge": challenge,
                "response": response,
            },
        )
        defer.returnValue(data)

    @defer.inlineCallbacks
    def get_or_create_user(self, requester, localpart, displayname, password_hash=None):
        """Creates a new user if the user does not exist,
        else revokes all previous access tokens and generates a new one.

        Args:
            localpart : The local part of the user ID to register. If None,
              one will be randomly generated.
        Returns:
            A tuple of (user_id, access_token).
        Raises:
            RegistrationError if there was a problem registering.

        NB this is only used in tests. TODO: move it to the test package!
        """
        if localpart is None:
            raise SynapseError(400, "Request must include user id")
        yield self.auth.check_auth_blocking()
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
            yield self.register_with_store(
                user_id=user_id,
                token=token,
                password_hash=password_hash,
                create_profile_with_displayname=user.localpart,
            )
        else:
            yield self._auth_handler.delete_access_tokens_for_user(user_id)
            yield self.store.add_access_token_to_user(user_id=user_id, token=token)

        if displayname is not None:
            logger.info("setting user display name: %s -> %s", user_id, displayname)
            yield self.profile_handler.set_displayname(
                user, requester, displayname, by_admin=True
            )

        defer.returnValue((user_id, token))

    @defer.inlineCallbacks
    def get_or_register_3pid_guest(self, medium, address, inviter_user_id):
        """Get a guest access token for a 3PID, creating a guest account if
        one doesn't already exist.

        Args:
            medium (str)
            address (str)
            inviter_user_id (str): The user ID who is trying to invite the
                3PID

        Returns:
            Deferred[(str, str)]: A 2-tuple of `(user_id, access_token)` of the
            3PID guest account.
        """
        access_token = yield self.store.get_3pid_guest_access_token(medium, address)
        if access_token:
            user_info = yield self.auth.get_user_by_access_token(access_token)

            defer.returnValue((user_info["user"].to_string(), access_token))

        user_id, access_token = yield self.register(
            generate_token=True, make_guest=True
        )
        access_token = yield self.store.save_or_get_3pid_guest_access_token(
            medium, address, access_token, inviter_user_id
        )

        defer.returnValue((user_id, access_token))

    @defer.inlineCallbacks
    def _join_user_to_room(self, requester, room_identifier):
        room_id = None
        room_member_handler = self.hs.get_room_member_handler()
        if RoomID.is_valid(room_identifier):
            room_id = room_identifier
        elif RoomAlias.is_valid(room_identifier):
            room_alias = RoomAlias.from_string(room_identifier)
            room_id, remote_room_hosts = (
                yield room_member_handler.lookup_room_alias(room_alias)
            )
            room_id = room_id.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )

        yield room_member_handler.update_membership(
            requester=requester,
            target=requester.user,
            room_id=room_id,
            remote_room_hosts=remote_room_hosts,
            action="join",
            ratelimit=False,
        )

    def register_with_store(
        self,
        user_id,
        token=None,
        password_hash=None,
        was_guest=False,
        make_guest=False,
        appservice_id=None,
        create_profile_with_displayname=None,
        admin=False,
        user_type=None,
        address=None,
    ):
        """Register user in the datastore.

        Args:
            user_id (str): The desired user ID to register.
            token (str): The desired access token to use for this user. If this
                is not None, the given access token is associated with the user
                id.
            password_hash (str|None): Optional. The password hash for this user.
            was_guest (bool): Optional. Whether this is a guest account being
                upgraded to a non-guest account.
            make_guest (boolean): True if the the new user should be guest,
                false to add a regular user account.
            appservice_id (str|None): The ID of the appservice registering the user.
            create_profile_with_displayname (unicode|None): Optionally create a
                profile for the user, setting their displayname to the given value
            admin (boolean): is an admin user?
            user_type (str|None): type of user. One of the values from
                api.constants.UserTypes, or None for a normal user.
            address (str|None): the IP address used to perform the registration.

        Returns:
            Deferred
        """
        # Don't rate limit for app services
        if appservice_id is None and address is not None:
            time_now = self.clock.time()

            allowed, time_allowed = self.ratelimiter.can_do_action(
                address,
                time_now_s=time_now,
                rate_hz=self.hs.config.rc_registration.per_second,
                burst_count=self.hs.config.rc_registration.burst_count,
            )

            if not allowed:
                raise LimitExceededError(
                    retry_after_ms=int(1000 * (time_allowed - time_now))
                )

        if self.hs.config.worker_app:
            return self._register_client(
                user_id=user_id,
                token=token,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                appservice_id=appservice_id,
                create_profile_with_displayname=create_profile_with_displayname,
                admin=admin,
                user_type=user_type,
                address=address,
            )
        else:
            return self.store.register(
                user_id=user_id,
                token=token,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                appservice_id=appservice_id,
                create_profile_with_displayname=create_profile_with_displayname,
                admin=admin,
                user_type=user_type,
            )

    @defer.inlineCallbacks
    def register_device(self, user_id, device_id, initial_display_name, is_guest=False):
        """Register a device for a user and generate an access token.

        Args:
            user_id (str): full canonical @user:id
            device_id (str|None): The device ID to check, or None to generate
                a new one.
            initial_display_name (str|None): An optional display name for the
                device.
            is_guest (bool): Whether this is a guest account

        Returns:
            defer.Deferred[tuple[str, str]]: Tuple of device ID and access token
        """

        if self.hs.config.worker_app:
            r = yield self._register_device_client(
                user_id=user_id,
                device_id=device_id,
                initial_display_name=initial_display_name,
                is_guest=is_guest,
            )
            defer.returnValue((r["device_id"], r["access_token"]))
        else:
            device_id = yield self.device_handler.check_device_registered(
                user_id, device_id, initial_display_name
            )
            if is_guest:
                access_token = self.macaroon_gen.generate_access_token(
                    user_id, ["guest = true"]
                )
            else:
                access_token = yield self._auth_handler.get_access_token_for_user_id(
                    user_id, device_id=device_id
                )

            defer.returnValue((device_id, access_token))

    @defer.inlineCallbacks
    def post_registration_actions(
        self, user_id, auth_result, access_token, bind_email, bind_msisdn
    ):
        """A user has completed registration

        Args:
            user_id (str): The user ID that consented
            auth_result (dict): The authenticated credentials of the newly
                registered user.
            access_token (str|None): The access token of the newly logged in
                device, or None if `inhibit_login` enabled.
            bind_email (bool): Whether to bind the email with the identity
                server.
            bind_msisdn (bool): Whether to bind the msisdn with the identity
                server.
        """
        if self.hs.config.worker_app:
            yield self._post_registration_client(
                user_id=user_id,
                auth_result=auth_result,
                access_token=access_token,
                bind_email=bind_email,
                bind_msisdn=bind_msisdn,
            )
            return

        if auth_result and LoginType.EMAIL_IDENTITY in auth_result:
            threepid = auth_result[LoginType.EMAIL_IDENTITY]
            # Necessary due to auth checks prior to the threepid being
            # written to the db
            if is_threepid_reserved(
                self.hs.config.mau_limits_reserved_threepids, threepid
            ):
                yield self.store.upsert_monthly_active_user(user_id)

            yield self._register_email_threepid(
                user_id, threepid, access_token, bind_email
            )

        if auth_result and LoginType.MSISDN in auth_result:
            threepid = auth_result[LoginType.MSISDN]
            yield self._register_msisdn_threepid(user_id, threepid, bind_msisdn)

        if auth_result and LoginType.TERMS in auth_result:
            yield self._on_user_consented(user_id, self.hs.config.user_consent_version)

    @defer.inlineCallbacks
    def _on_user_consented(self, user_id, consent_version):
        """A user consented to the terms on registration

        Args:
            user_id (str): The user ID that consented.
            consent_version (str): version of the policy the user has
                consented to.
        """
        logger.info("%s has consented to the privacy policy", user_id)
        yield self.store.user_set_consent_version(user_id, consent_version)
        yield self.post_consent_actions(user_id)

    @defer.inlineCallbacks
    def _register_email_threepid(self, user_id, threepid, token, bind_email):
        """Add an email address as a 3pid identifier

        Also adds an email pusher for the email address, if configured in the
        HS config

        Also optionally binds emails to the given user_id on the identity server

        Must be called on master.

        Args:
            user_id (str): id of user
            threepid (object): m.login.email.identity auth response
            token (str|None): access_token for the user, or None if not logged
                in.
            bind_email (bool): true if the client requested the email to be
                bound at the identity server
        Returns:
            defer.Deferred:
        """
        reqd = ("medium", "address", "validated_at")
        if any(x not in threepid for x in reqd):
            # This will only happen if the ID server returns a malformed response
            logger.info("Can't add incomplete 3pid")
            return

        yield self._auth_handler.add_threepid(
            user_id, threepid["medium"], threepid["address"], threepid["validated_at"]
        )

        # And we add an email pusher for them by default, but only
        # if email notifications are enabled (so people don't start
        # getting mail spam where they weren't before if email
        # notifs are set up on a home server)
        if (
            self.hs.config.email_enable_notifs
            and self.hs.config.email_notif_for_new_users
            and token
        ):
            # Pull the ID of the access token back out of the db
            # It would really make more sense for this to be passed
            # up when the access token is saved, but that's quite an
            # invasive change I'd rather do separately.
            user_tuple = yield self.store.get_user_by_access_token(token)
            token_id = user_tuple["token_id"]

            yield self.pusher_pool.add_pusher(
                user_id=user_id,
                access_token=token_id,
                kind="email",
                app_id="m.email",
                app_display_name="Email Notifications",
                device_display_name=threepid["address"],
                pushkey=threepid["address"],
                lang=None,  # We don't know a user's language here
                data={},
            )

        if bind_email:
            logger.info("bind_email specified: binding")
            logger.debug("Binding emails %s to %s" % (threepid, user_id))
            yield self.identity_handler.bind_threepid(
                threepid["threepid_creds"], user_id
            )
        else:
            logger.info("bind_email not specified: not binding email")

    @defer.inlineCallbacks
    def _register_msisdn_threepid(self, user_id, threepid, bind_msisdn):
        """Add a phone number as a 3pid identifier

        Also optionally binds msisdn to the given user_id on the identity server

        Must be called on master.

        Args:
            user_id (str): id of user
            threepid (object): m.login.msisdn auth response
            token (str): access_token for the user
            bind_email (bool): true if the client requested the email to be
                bound at the identity server
        Returns:
            defer.Deferred:
        """
        try:
            assert_params_in_dict(threepid, ["medium", "address", "validated_at"])
        except SynapseError as ex:
            if ex.errcode == Codes.MISSING_PARAM:
                # This will only happen if the ID server returns a malformed response
                logger.info("Can't add incomplete 3pid")
                defer.returnValue(None)
            raise

        yield self._auth_handler.add_threepid(
            user_id, threepid["medium"], threepid["address"], threepid["validated_at"]
        )

        if bind_msisdn:
            logger.info("bind_msisdn specified: binding")
            logger.debug("Binding msisdn %s to %s", threepid, user_id)
            yield self.identity_handler.bind_threepid(
                threepid["threepid_creds"], user_id
            )
        else:
            logger.info("bind_msisdn not specified: not binding msisdn")
