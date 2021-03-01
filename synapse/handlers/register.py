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
from typing import TYPE_CHECKING, Iterable, List, Optional, Tuple

from synapse import types
from synapse.api.constants import MAX_USERID_LENGTH, EventTypes, JoinRules, LoginType
from synapse.api.errors import AuthError, Codes, ConsentNotGivenError, SynapseError
from synapse.appservice import ApplicationService
from synapse.config.server import is_threepid_reserved
from synapse.http.servlet import assert_params_in_dict
from synapse.replication.http.login import RegisterDeviceReplicationServlet
from synapse.replication.http.register import (
    ReplicationPostRegisterActionsServlet,
    ReplicationRegisterServlet,
)
from synapse.spam_checker_api import RegistrationBehaviour
from synapse.storage.state import StateFilter
from synapse.types import RoomAlias, UserID, create_requester

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


class RegistrationHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self.profile_handler = hs.get_profile_handler()
        self.user_directory_handler = hs.get_user_directory_handler()
        self.identity_handler = self.hs.get_identity_handler()
        self.ratelimiter = hs.get_registration_ratelimiter()
        self.macaroon_gen = hs.get_macaroon_generator()
        self._server_notices_mxid = hs.config.server_notices_mxid
        self._server_name = hs.hostname

        self.spam_checker = hs.get_spam_checker()

        if hs.config.worker_app:
            self._register_client = ReplicationRegisterServlet.make_client(hs)
            self._register_device_client = RegisterDeviceReplicationServlet.make_client(
                hs
            )
            self._post_registration_client = (
                ReplicationPostRegisterActionsServlet.make_client(hs)
            )
        else:
            self.device_handler = hs.get_device_handler()
            self.pusher_pool = hs.get_pusherpool()

        self.session_lifetime = hs.config.session_lifetime

    async def check_username(
        self,
        localpart: str,
        guest_access_token: Optional[str] = None,
        assigned_user_id: Optional[str] = None,
    ):
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

        users = await self.store.get_users_by_id_case_insensitive(user_id)
        if users:
            if not guest_access_token:
                raise SynapseError(
                    400, "User ID already taken.", errcode=Codes.USER_IN_USE
                )
            user_data = await self.auth.get_user_by_access_token(guest_access_token)
            if (
                not user_data.is_guest
                or UserID.from_string(user_data.user_id).localpart != localpart
            ):
                raise AuthError(
                    403,
                    "Cannot register taken user ID without valid guest "
                    "credentials for that user.",
                    errcode=Codes.FORBIDDEN,
                )

        if guest_access_token is None:
            try:
                int(localpart)
                raise SynapseError(
                    400,
                    "Numeric user IDs are reserved for guest users.",
                    errcode=Codes.INVALID_USERNAME,
                )
            except ValueError:
                pass

    async def register_user(
        self,
        localpart: Optional[str] = None,
        password_hash: Optional[str] = None,
        guest_access_token: Optional[str] = None,
        make_guest: bool = False,
        admin: bool = False,
        threepid: Optional[dict] = None,
        user_type: Optional[str] = None,
        default_display_name: Optional[str] = None,
        address: Optional[str] = None,
        bind_emails: Iterable[str] = [],
        by_admin: bool = False,
        user_agent_ips: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        """Registers a new client on the server.

        Args:
            localpart: The local part of the user ID to register. If None,
              one will be generated.
            password_hash: The hashed password to assign to this user so they can
              login again. This can be None which means they cannot login again
              via a password (e.g. the user is an application service user).
            guest_access_token: The access token used when this was a guest
                account.
            make_guest: True if the the new user should be guest,
                false to add a regular user account.
            admin: True if the user should be registered as a server admin.
            threepid: The threepid used for registering, if any.
            user_type: type of user. One of the values from
              api.constants.UserTypes, or None for a normal user.
            default_display_name: if set, the new user's displayname
              will be set to this. Defaults to 'localpart'.
            address: the IP address used to perform the registration.
            bind_emails: list of emails to bind to this account.
            by_admin: True if this registration is being made via the
              admin api, otherwise False.
            user_agent_ips: Tuples of IP addresses and user-agents used
                during the registration process.
        Returns:
            The registere user_id.
        Raises:
            SynapseError if there was a problem registering.
        """
        self.check_registration_ratelimit(address)

        result = await self.spam_checker.check_registration_for_spam(
            threepid,
            localpart,
            user_agent_ips or [],
        )

        if result == RegistrationBehaviour.DENY:
            logger.info(
                "Blocked registration of %r",
                localpart,
            )
            # We return a 429 to make it not obvious that they've been
            # denied.
            raise SynapseError(429, "Rate limited")

        shadow_banned = result == RegistrationBehaviour.SHADOW_BAN
        if shadow_banned:
            logger.info(
                "Shadow banning registration of %r",
                localpart,
            )

        # do not check_auth_blocking if the call is coming through the Admin API
        if not by_admin:
            await self.auth.check_auth_blocking(threepid=threepid)

        if localpart is not None:
            await self.check_username(localpart, guest_access_token=guest_access_token)

            was_guest = guest_access_token is not None

            user = UserID(localpart, self.hs.hostname)
            user_id = user.to_string()

            if was_guest:
                # If the user was a guest then they already have a profile
                default_display_name = None

            elif default_display_name is None:
                default_display_name = localpart

            await self.register_with_store(
                user_id=user_id,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                create_profile_with_displayname=default_display_name,
                admin=admin,
                user_type=user_type,
                address=address,
                shadow_banned=shadow_banned,
            )

            if self.hs.config.user_directory_search_all_users:
                profile = await self.store.get_profileinfo(localpart)
                await self.user_directory_handler.handle_local_profile_change(
                    user_id, profile
                )

        else:
            # autogen a sequential user ID
            fail_count = 0
            # If a default display name is not given, generate one.
            generate_display_name = default_display_name is None
            # This breaks on successful registration *or* errors after 10 failures.
            while True:
                # Fail after being unable to find a suitable ID a few times
                if fail_count > 10:
                    raise SynapseError(500, "Unable to find a suitable guest user ID")

                localpart = await self.store.generate_user_id()
                user = UserID(localpart, self.hs.hostname)
                user_id = user.to_string()
                self.check_user_id_not_appservice_exclusive(user_id)
                if generate_display_name:
                    default_display_name = localpart
                try:
                    await self.register_with_store(
                        user_id=user_id,
                        password_hash=password_hash,
                        make_guest=make_guest,
                        create_profile_with_displayname=default_display_name,
                        address=address,
                        shadow_banned=shadow_banned,
                    )

                    # Successfully registered
                    break
                except SynapseError:
                    # if user id is taken, just generate another
                    fail_count += 1

        if not self.hs.config.user_consent_at_registration:
            if not self.hs.config.auto_join_rooms_for_guests and make_guest:
                logger.info(
                    "Skipping auto-join for %s because auto-join for guests is disabled",
                    user_id,
                )
            else:
                await self._auto_join_rooms(user_id)
        else:
            logger.info(
                "Skipping auto-join for %s because consent is required at registration",
                user_id,
            )

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
            await self._register_email_threepid(user_id, threepid_dict, None)

        return user_id

    async def _create_and_join_rooms(self, user_id: str) -> None:
        """
        Create the auto-join rooms and join or invite the user to them.

        This should only be called when the first "real" user registers.

        Args:
            user_id: The user to join
        """
        # Getting the handlers during init gives a dependency loop.
        room_creation_handler = self.hs.get_room_creation_handler()
        room_member_handler = self.hs.get_room_member_handler()

        # Generate a stub for how the rooms will be configured.
        stub_config = {
            "preset": self.hs.config.registration.autocreate_auto_join_room_preset,
        }

        # If the configuration providers a user ID to create rooms with, use
        # that instead of the first user registered.
        requires_join = False
        if self.hs.config.registration.auto_join_user_id:
            fake_requester = create_requester(
                self.hs.config.registration.auto_join_user_id,
                authenticated_entity=self._server_name,
            )

            # If the room requires an invite, add the user to the list of invites.
            if self.hs.config.registration.auto_join_room_requires_invite:
                stub_config["invite"] = [user_id]

            # If the room is being created by a different user, the first user
            # registered needs to join it. Note that in the case of an invitation
            # being necessary this will occur after the invite was sent.
            requires_join = True
        else:
            fake_requester = create_requester(
                user_id, authenticated_entity=self._server_name
            )

        # Choose whether to federate the new room.
        if not self.hs.config.registration.autocreate_auto_join_rooms_federated:
            stub_config["creation_content"] = {"m.federate": False}

        for r in self.hs.config.registration.auto_join_rooms:
            logger.info("Auto-joining %s to %s", user_id, r)

            try:
                room_alias = RoomAlias.from_string(r)

                if self.hs.hostname != room_alias.domain:
                    logger.warning(
                        "Cannot create room alias %s, "
                        "it does not match server domain",
                        r,
                    )
                else:
                    # A shallow copy is OK here since the only key that is
                    # modified is room_alias_name.
                    config = stub_config.copy()
                    # create room expects the localpart of the room alias
                    config["room_alias_name"] = room_alias.localpart

                    info, _ = await room_creation_handler.create_room(
                        fake_requester,
                        config=config,
                        ratelimit=False,
                    )

                    # If the room does not require an invite, but another user
                    # created it, then ensure the first user joins it.
                    if requires_join:
                        await room_member_handler.update_membership(
                            requester=create_requester(
                                user_id, authenticated_entity=self._server_name
                            ),
                            target=UserID.from_string(user_id),
                            room_id=info["room_id"],
                            # Since it was just created, there are no remote hosts.
                            remote_room_hosts=[],
                            action="join",
                            ratelimit=False,
                        )
            except Exception as e:
                logger.error("Failed to join new user to %r: %r", r, e)

    async def _join_rooms(self, user_id: str) -> None:
        """
        Join or invite the user to the auto-join rooms.

        Args:
            user_id: The user to join
        """
        room_member_handler = self.hs.get_room_member_handler()

        for r in self.hs.config.registration.auto_join_rooms:
            logger.info("Auto-joining %s to %s", user_id, r)

            try:
                room_alias = RoomAlias.from_string(r)

                if RoomAlias.is_valid(r):
                    (
                        room_id,
                        remote_room_hosts,
                    ) = await room_member_handler.lookup_room_alias(room_alias)
                    room_id = room_id.to_string()
                else:
                    raise SynapseError(
                        400, "%s was not legal room ID or room alias" % (r,)
                    )

                # Calculate whether the room requires an invite or can be
                # joined directly. Note that unless a join rule of public exists,
                # it is treated as requiring an invite.
                requires_invite = True

                state = await self.store.get_filtered_current_state_ids(
                    room_id, StateFilter.from_types([(EventTypes.JoinRules, "")])
                )

                event_id = state.get((EventTypes.JoinRules, ""))
                if event_id:
                    join_rules_event = await self.store.get_event(
                        event_id, allow_none=True
                    )
                    if join_rules_event:
                        join_rule = join_rules_event.content.get("join_rule", None)
                        requires_invite = join_rule and join_rule != JoinRules.PUBLIC

                # Send the invite, if necessary.
                if requires_invite:
                    # If an invite is required, there must be a auto-join user ID.
                    assert self.hs.config.registration.auto_join_user_id

                    await room_member_handler.update_membership(
                        requester=create_requester(
                            self.hs.config.registration.auto_join_user_id,
                            authenticated_entity=self._server_name,
                        ),
                        target=UserID.from_string(user_id),
                        room_id=room_id,
                        remote_room_hosts=remote_room_hosts,
                        action="invite",
                        ratelimit=False,
                    )

                # Send the join.
                await room_member_handler.update_membership(
                    requester=create_requester(
                        user_id, authenticated_entity=self._server_name
                    ),
                    target=UserID.from_string(user_id),
                    room_id=room_id,
                    remote_room_hosts=remote_room_hosts,
                    action="join",
                    ratelimit=False,
                )

            except ConsentNotGivenError as e:
                # Technically not necessary to pull out this error though
                # moving away from bare excepts is a good thing to do.
                logger.error("Failed to join new user to %r: %r", r, e)
            except Exception as e:
                logger.error("Failed to join new user to %r: %r", r, e)

    async def _auto_join_rooms(self, user_id: str) -> None:
        """Automatically joins users to auto join rooms - creating the room in the first place
        if the user is the first to be created.

        Args:
            user_id: The user to join
        """
        # auto-join the user to any rooms we're supposed to dump them into

        # try to create the room if we're the first real user on the server. Note
        # that an auto-generated support or bot user is not a real user and will never be
        # the user to create the room
        should_auto_create_rooms = False
        is_real_user = await self.store.is_real_user(user_id)
        if self.hs.config.registration.autocreate_auto_join_rooms and is_real_user:
            count = await self.store.count_real_users()
            should_auto_create_rooms = count == 1

        if should_auto_create_rooms:
            await self._create_and_join_rooms(user_id)
        else:
            await self._join_rooms(user_id)

    async def post_consent_actions(self, user_id: str) -> None:
        """A series of registration actions that can only be carried out once consent
        has been granted

        Args:
            user_id: The user to join
        """
        await self._auto_join_rooms(user_id)

    async def appservice_register(self, user_localpart: str, as_token: str) -> str:
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

        self.check_user_id_not_appservice_exclusive(user_id, allowed_appservice=service)

        await self.register_with_store(
            user_id=user_id,
            password_hash="",
            appservice_id=service_id,
            create_profile_with_displayname=user.localpart,
        )
        return user_id

    def check_user_id_not_appservice_exclusive(
        self, user_id: str, allowed_appservice: Optional[ApplicationService] = None
    ) -> None:
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

    def check_registration_ratelimit(self, address: Optional[str]) -> None:
        """A simple helper method to check whether the registration rate limit has been hit
        for a given IP address

        Args:
            address: the IP address used to perform the registration. If this is
                None, no ratelimiting will be performed.

        Raises:
            LimitExceededError: If the rate limit has been exceeded.
        """
        if not address:
            return

        self.ratelimiter.ratelimit(address)

    async def register_with_store(
        self,
        user_id: str,
        password_hash: Optional[str] = None,
        was_guest: bool = False,
        make_guest: bool = False,
        appservice_id: Optional[str] = None,
        create_profile_with_displayname: Optional[str] = None,
        admin: bool = False,
        user_type: Optional[str] = None,
        address: Optional[str] = None,
        shadow_banned: bool = False,
    ) -> None:
        """Register user in the datastore.

        Args:
            user_id: The desired user ID to register.
            password_hash: Optional. The password hash for this user.
            was_guest: Optional. Whether this is a guest account being
                upgraded to a non-guest account.
            make_guest: True if the the new user should be guest,
                false to add a regular user account.
            appservice_id: The ID of the appservice registering the user.
            create_profile_with_displayname: Optionally create a
                profile for the user, setting their displayname to the given value
            admin: is an admin user?
            user_type: type of user. One of the values from
                api.constants.UserTypes, or None for a normal user.
            address: the IP address used to perform the registration.
            shadow_banned: Whether to shadow-ban the user
        """
        if self.hs.config.worker_app:
            await self._register_client(
                user_id=user_id,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                appservice_id=appservice_id,
                create_profile_with_displayname=create_profile_with_displayname,
                admin=admin,
                user_type=user_type,
                address=address,
                shadow_banned=shadow_banned,
            )
        else:
            await self.store.register_user(
                user_id=user_id,
                password_hash=password_hash,
                was_guest=was_guest,
                make_guest=make_guest,
                appservice_id=appservice_id,
                create_profile_with_displayname=create_profile_with_displayname,
                admin=admin,
                user_type=user_type,
                shadow_banned=shadow_banned,
            )

    async def register_device(
        self,
        user_id: str,
        device_id: Optional[str],
        initial_display_name: Optional[str],
        is_guest: bool = False,
        is_appservice_ghost: bool = False,
    ) -> Tuple[str, str]:
        """Register a device for a user and generate an access token.

        The access token will be limited by the homeserver's session_lifetime config.

        Args:
            user_id: full canonical @user:id
            device_id: The device ID to check, or None to generate a new one.
            initial_display_name: An optional display name for the device.
            is_guest: Whether this is a guest account

        Returns:
            Tuple of device ID and access token
        """

        if self.hs.config.worker_app:
            r = await self._register_device_client(
                user_id=user_id,
                device_id=device_id,
                initial_display_name=initial_display_name,
                is_guest=is_guest,
                is_appservice_ghost=is_appservice_ghost,
            )
            return r["device_id"], r["access_token"]

        valid_until_ms = None
        if self.session_lifetime is not None:
            if is_guest:
                raise Exception(
                    "session_lifetime is not currently implemented for guest access"
                )
            valid_until_ms = self.clock.time_msec() + self.session_lifetime

        registered_device_id = await self.device_handler.check_device_registered(
            user_id, device_id, initial_display_name
        )
        if is_guest:
            assert valid_until_ms is None
            access_token = self.macaroon_gen.generate_access_token(
                user_id, ["guest = true"]
            )
        else:
            access_token = await self._auth_handler.get_access_token_for_user_id(
                user_id,
                device_id=registered_device_id,
                valid_until_ms=valid_until_ms,
                is_appservice_ghost=is_appservice_ghost,
            )

        return (registered_device_id, access_token)

    async def post_registration_actions(
        self, user_id: str, auth_result: dict, access_token: Optional[str]
    ) -> None:
        """A user has completed registration

        Args:
            user_id: The user ID that consented
            auth_result: The authenticated credentials of the newly registered user.
            access_token: The access token of the newly logged in device, or
                None if `inhibit_login` enabled.
        """
        # TODO: 3pid registration can actually happen on the workers. Consider
        # refactoring it.
        if self.hs.config.worker_app:
            await self._post_registration_client(
                user_id=user_id, auth_result=auth_result, access_token=access_token
            )
            return

        if auth_result and LoginType.EMAIL_IDENTITY in auth_result:
            threepid = auth_result[LoginType.EMAIL_IDENTITY]
            # Necessary due to auth checks prior to the threepid being
            # written to the db
            if is_threepid_reserved(
                self.hs.config.mau_limits_reserved_threepids, threepid
            ):
                await self.store.upsert_monthly_active_user(user_id)

            await self._register_email_threepid(user_id, threepid, access_token)

        if auth_result and LoginType.MSISDN in auth_result:
            threepid = auth_result[LoginType.MSISDN]
            await self._register_msisdn_threepid(user_id, threepid)

        if auth_result and LoginType.TERMS in auth_result:
            await self._on_user_consented(user_id, self.hs.config.user_consent_version)

    async def _on_user_consented(self, user_id: str, consent_version: str) -> None:
        """A user consented to the terms on registration

        Args:
            user_id: The user ID that consented.
            consent_version: version of the policy the user has consented to.
        """
        logger.info("%s has consented to the privacy policy", user_id)
        await self.store.user_set_consent_version(user_id, consent_version)
        await self.post_consent_actions(user_id)

    async def _register_email_threepid(
        self, user_id: str, threepid: dict, token: Optional[str]
    ) -> None:
        """Add an email address as a 3pid identifier

        Also adds an email pusher for the email address, if configured in the
        HS config

        Must be called on master.

        Args:
            user_id: id of user
            threepid: m.login.email.identity auth response
            token: access_token for the user, or None if not logged in.
        """
        reqd = ("medium", "address", "validated_at")
        if any(x not in threepid for x in reqd):
            # This will only happen if the ID server returns a malformed response
            logger.info("Can't add incomplete 3pid")
            return

        await self._auth_handler.add_threepid(
            user_id,
            threepid["medium"],
            threepid["address"],
            threepid["validated_at"],
        )

        # And we add an email pusher for them by default, but only
        # if email notifications are enabled (so people don't start
        # getting mail spam where they weren't before if email
        # notifs are set up on a homeserver)
        if (
            self.hs.config.email_enable_notifs
            and self.hs.config.email_notif_for_new_users
            and token
        ):
            # Pull the ID of the access token back out of the db
            # It would really make more sense for this to be passed
            # up when the access token is saved, but that's quite an
            # invasive change I'd rather do separately.
            user_tuple = await self.store.get_user_by_access_token(token)
            # The token better still exist.
            assert user_tuple
            token_id = user_tuple.token_id

            await self.pusher_pool.add_pusher(
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

    async def _register_msisdn_threepid(self, user_id: str, threepid: dict) -> None:
        """Add a phone number as a 3pid identifier

        Must be called on master.

        Args:
            user_id: id of user
            threepid: m.login.msisdn auth response
        """
        try:
            assert_params_in_dict(threepid, ["medium", "address", "validated_at"])
        except SynapseError as ex:
            if ex.errcode == Codes.MISSING_PARAM:
                # This will only happen if the ID server returns a malformed response
                logger.info("Can't add incomplete 3pid")
                return None
            raise

        await self._auth_handler.add_threepid(
            user_id,
            threepid["medium"],
            threepid["address"],
            threepid["validated_at"],
        )
