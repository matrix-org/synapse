# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import argparse
from typing import Any, Optional

from synapse.api.constants import RoomCreationPreset
from synapse.config._base import Config, ConfigError
from synapse.types import JsonDict, RoomAlias, UserID
from synapse.util.stringutils import random_string_with_symbols, strtobool


class RegistrationConfig(Config):
    section = "registration"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.enable_registration = strtobool(
            str(config.get("enable_registration", False))
        )
        if "disable_registration" in config:
            self.enable_registration = not strtobool(
                str(config["disable_registration"])
            )

        self.enable_registration_without_verification = strtobool(
            str(config.get("enable_registration_without_verification", False))
        )

        self.registrations_require_3pid = config.get("registrations_require_3pid", [])
        self.allowed_local_3pids = config.get("allowed_local_3pids", [])
        self.enable_3pid_lookup = config.get("enable_3pid_lookup", True)
        self.registration_requires_token = config.get(
            "registration_requires_token", False
        )
        self.enable_registration_token_3pid_bypass = config.get(
            "enable_registration_token_3pid_bypass", False
        )
        self.registration_shared_secret = config.get("registration_shared_secret")

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)

        account_threepid_delegates = config.get("account_threepid_delegates") or {}
        self.account_threepid_delegate_email = account_threepid_delegates.get("email")
        self.account_threepid_delegate_msisdn = account_threepid_delegates.get("msisdn")
        self.default_identity_server = config.get("default_identity_server")
        self.allow_guest_access = config.get("allow_guest_access", False)

        if config.get("invite_3pid_guest", False):
            raise ConfigError("invite_3pid_guest is no longer supported")

        self.auto_join_rooms = config.get("auto_join_rooms", [])
        for room_alias in self.auto_join_rooms:
            if not RoomAlias.is_valid(room_alias):
                raise ConfigError("Invalid auto_join_rooms entry %s" % (room_alias,))

        # Options for creating auto-join rooms if they do not exist yet.
        self.autocreate_auto_join_rooms = config.get("autocreate_auto_join_rooms", True)
        self.autocreate_auto_join_rooms_federated = config.get(
            "autocreate_auto_join_rooms_federated", True
        )
        self.autocreate_auto_join_room_preset = (
            config.get("autocreate_auto_join_room_preset")
            or RoomCreationPreset.PUBLIC_CHAT
        )
        self.auto_join_room_requires_invite = self.autocreate_auto_join_room_preset in {
            RoomCreationPreset.PRIVATE_CHAT,
            RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
        }

        # Pull the creator/inviter from the configuration, this gets used to
        # send invites for invite-only rooms.
        mxid_localpart = config.get("auto_join_mxid_localpart")
        self.auto_join_user_id = None
        if mxid_localpart:
            # Convert the localpart to a full mxid.
            self.auto_join_user_id = UserID(
                mxid_localpart, self.root.server.server_name
            ).to_string()

        if self.autocreate_auto_join_rooms:
            # Ensure the preset is a known value.
            if self.autocreate_auto_join_room_preset not in {
                RoomCreationPreset.PUBLIC_CHAT,
                RoomCreationPreset.PRIVATE_CHAT,
                RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
            }:
                raise ConfigError("Invalid value for autocreate_auto_join_room_preset")
            # If the preset requires invitations to be sent, ensure there's a
            # configured user to send them from.
            if self.auto_join_room_requires_invite:
                if not mxid_localpart:
                    raise ConfigError(
                        "The configuration option `auto_join_mxid_localpart` is required if "
                        "`autocreate_auto_join_room_preset` is set to private_chat or trusted_private_chat, such that "
                        "Synapse knows who to send invitations from. Please "
                        "configure `auto_join_mxid_localpart`."
                    )

        self.auto_join_rooms_for_guests = config.get("auto_join_rooms_for_guests", True)

        self.enable_set_displayname = config.get("enable_set_displayname", True)
        self.enable_set_avatar_url = config.get("enable_set_avatar_url", True)
        self.enable_3pid_changes = config.get("enable_3pid_changes", True)

        self.disable_msisdn_registration = config.get(
            "disable_msisdn_registration", False
        )

        session_lifetime = config.get("session_lifetime")
        if session_lifetime is not None:
            session_lifetime = self.parse_duration(session_lifetime)
        self.session_lifetime = session_lifetime

        # The `refreshable_access_token_lifetime` applies for tokens that can be renewed
        # using a refresh token, as per MSC2918.
        # If it is `None`, the refresh token mechanism is disabled.
        refreshable_access_token_lifetime = config.get(
            "refreshable_access_token_lifetime",
            "5m",
        )
        if refreshable_access_token_lifetime is not None:
            refreshable_access_token_lifetime = self.parse_duration(
                refreshable_access_token_lifetime
            )
        self.refreshable_access_token_lifetime: Optional[
            int
        ] = refreshable_access_token_lifetime

        if (
            self.session_lifetime is not None
            and "refreshable_access_token_lifetime" in config
        ):
            if self.session_lifetime < self.refreshable_access_token_lifetime:
                raise ConfigError(
                    "Both `session_lifetime` and `refreshable_access_token_lifetime` "
                    "configuration options have been set, but `refreshable_access_token_lifetime` "
                    " exceeds `session_lifetime`!"
                )

        # The `nonrefreshable_access_token_lifetime` applies for tokens that can NOT be
        # refreshed using a refresh token.
        # If it is None, then these tokens last for the entire length of the session,
        # which is infinite by default.
        # The intention behind this configuration option is to help with requiring
        # all clients to use refresh tokens, if the homeserver administrator requires.
        nonrefreshable_access_token_lifetime = config.get(
            "nonrefreshable_access_token_lifetime",
            None,
        )
        if nonrefreshable_access_token_lifetime is not None:
            nonrefreshable_access_token_lifetime = self.parse_duration(
                nonrefreshable_access_token_lifetime
            )
        self.nonrefreshable_access_token_lifetime = nonrefreshable_access_token_lifetime

        if (
            self.session_lifetime is not None
            and self.nonrefreshable_access_token_lifetime is not None
        ):
            if self.session_lifetime < self.nonrefreshable_access_token_lifetime:
                raise ConfigError(
                    "Both `session_lifetime` and `nonrefreshable_access_token_lifetime` "
                    "configuration options have been set, but `nonrefreshable_access_token_lifetime` "
                    " exceeds `session_lifetime`!"
                )

        refresh_token_lifetime = config.get("refresh_token_lifetime")
        if refresh_token_lifetime is not None:
            refresh_token_lifetime = self.parse_duration(refresh_token_lifetime)
        self.refresh_token_lifetime: Optional[int] = refresh_token_lifetime

        if (
            self.session_lifetime is not None
            and self.refresh_token_lifetime is not None
        ):
            if self.session_lifetime < self.refresh_token_lifetime:
                raise ConfigError(
                    "Both `session_lifetime` and `refresh_token_lifetime` "
                    "configuration options have been set, but `refresh_token_lifetime` "
                    " exceeds `session_lifetime`!"
                )

        # The fallback template used for authenticating using a registration token
        self.registration_token_template = self.read_template("registration_token.html")

        # The success template used during fallback auth.
        self.fallback_success_template = self.read_template("auth_success.html")

        self.inhibit_user_in_use_error = config.get("inhibit_user_in_use_error", False)

    def generate_config_section(
        self, generate_secrets: bool = False, **kwargs: Any
    ) -> str:
        if generate_secrets:
            registration_shared_secret = 'registration_shared_secret: "%s"' % (
                random_string_with_symbols(50),
            )
        else:
            registration_shared_secret = "#registration_shared_secret: <PRIVATE STRING>"

        return (
            """\
        ## Registration ##
        #
        # Registration can be rate-limited using the parameters in the "Ratelimiting"
        # section of this file.

        # Enable registration for new users. Defaults to 'false'. It is highly recommended that if you enable registration,
        # you use either captcha, email, or token-based verification to verify that new users are not bots. In order to enable registration
        # without any verification, you must also set `enable_registration_without_verification`, found below.
        #
        #enable_registration: false

        # Enable registration without email or captcha verification. Note: this option is *not* recommended,
        # as registration without verification is a known vector for spam and abuse. Defaults to false. Has no effect
        # unless `enable_registration` is also enabled.
        #
        #enable_registration_without_verification: true

        # Time that a user's session remains valid for, after they log in.
        #
        # Note that this is not currently compatible with guest logins.
        #
        # Note also that this is calculated at login time: changes are not applied
        # retrospectively to users who have already logged in.
        #
        # By default, this is infinite.
        #
        #session_lifetime: 24h

        # Time that an access token remains valid for, if the session is
        # using refresh tokens.
        # For more information about refresh tokens, please see the manual.
        # Note that this only applies to clients which advertise support for
        # refresh tokens.
        #
        # Note also that this is calculated at login time and refresh time:
        # changes are not applied to existing sessions until they are refreshed.
        #
        # By default, this is 5 minutes.
        #
        #refreshable_access_token_lifetime: 5m

        # Time that a refresh token remains valid for (provided that it is not
        # exchanged for another one first).
        # This option can be used to automatically log-out inactive sessions.
        # Please see the manual for more information.
        #
        # Note also that this is calculated at login time and refresh time:
        # changes are not applied to existing sessions until they are refreshed.
        #
        # By default, this is infinite.
        #
        #refresh_token_lifetime: 24h

        # Time that an access token remains valid for, if the session is NOT
        # using refresh tokens.
        # Please note that not all clients support refresh tokens, so setting
        # this to a short value may be inconvenient for some users who will
        # then be logged out frequently.
        #
        # Note also that this is calculated at login time: changes are not applied
        # retrospectively to existing sessions for users that have already logged in.
        #
        # By default, this is infinite.
        #
        #nonrefreshable_access_token_lifetime: 24h

        # The user must provide all of the below types of 3PID when registering.
        #
        #registrations_require_3pid:
        #  - email
        #  - msisdn

        # Explicitly disable asking for MSISDNs from the registration
        # flow (overrides registrations_require_3pid if MSISDNs are set as required)
        #
        #disable_msisdn_registration: true

        # Mandate that users are only allowed to associate certain formats of
        # 3PIDs with accounts on this server.
        #
        #allowed_local_3pids:
        #  - medium: email
        #    pattern: '^[^@]+@matrix\\.org$'
        #  - medium: email
        #    pattern: '^[^@]+@vector\\.im$'
        #  - medium: msisdn
        #    pattern: '\\+44'

        # Enable 3PIDs lookup requests to identity servers from this server.
        #
        #enable_3pid_lookup: true

        # Require users to submit a token during registration.
        # Tokens can be managed using the admin API:
        # https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/registration_tokens.html
        # Note that `enable_registration` must be set to `true`.
        # Disabling this option will not delete any tokens previously generated.
        # Defaults to false. Uncomment the following to require tokens:
        #
        #registration_requires_token: true

        # Allow users to submit a token during registration to bypass any required 3pid
        # steps configured in `registrations_require_3pid`.
        # Defaults to false, requiring that registration tokens (if enabled) complete a 3pid flow.
        #
        #enable_registration_token_3pid_bypass: false

        # If set, allows registration of standard or admin accounts by anyone who
        # has the shared secret, even if registration is otherwise disabled.
        #
        %(registration_shared_secret)s

        # Set the number of bcrypt rounds used to generate password hash.
        # Larger numbers increase the work factor needed to generate the hash.
        # The default number is 12 (which equates to 2^12 rounds).
        # N.B. that increasing this will exponentially increase the time required
        # to register or login - e.g. 24 => 2^24 rounds which will take >20 mins.
        #
        #bcrypt_rounds: 12

        # Allows users to register as guests without a password/email/etc, and
        # participate in rooms hosted on this server which have been made
        # accessible to anonymous users.
        #
        #allow_guest_access: false

        # The identity server which we suggest that clients should use when users log
        # in on this server.
        #
        # (By default, no suggestion is made, so it is left up to the client.
        # This setting is ignored unless public_baseurl is also explicitly set.)
        #
        #default_identity_server: https://matrix.org

        # Handle threepid (email/phone etc) registration and password resets through a set of
        # *trusted* identity servers. Note that this allows the configured identity server to
        # reset passwords for accounts!
        #
        # Be aware that if `email` is not set, and SMTP options have not been
        # configured in the email config block, registration and user password resets via
        # email will be globally disabled.
        #
        # Additionally, if `msisdn` is not set, registration and password resets via msisdn
        # will be disabled regardless, and users will not be able to associate an msisdn
        # identifier to their account. This is due to Synapse currently not supporting
        # any method of sending SMS messages on its own.
        #
        # To enable using an identity server for operations regarding a particular third-party
        # identifier type, set the value to the URL of that identity server as shown in the
        # examples below.
        #
        # Servers handling the these requests must answer the `/requestToken` endpoints defined
        # by the Matrix Identity Service API specification:
        # https://matrix.org/docs/spec/identity_service/latest
        #
        account_threepid_delegates:
            #email: https://example.com     # Delegate email sending to example.com
            #msisdn: http://localhost:8090  # Delegate SMS sending to this local process

        # Whether users are allowed to change their displayname after it has
        # been initially set. Useful when provisioning users based on the
        # contents of a third-party directory.
        #
        # Does not apply to server administrators. Defaults to 'true'
        #
        #enable_set_displayname: false

        # Whether users are allowed to change their avatar after it has been
        # initially set. Useful when provisioning users based on the contents
        # of a third-party directory.
        #
        # Does not apply to server administrators. Defaults to 'true'
        #
        #enable_set_avatar_url: false

        # Whether users can change the 3PIDs associated with their accounts
        # (email address and msisdn).
        #
        # Defaults to 'true'
        #
        #enable_3pid_changes: false

        # Users who register on this homeserver will automatically be joined
        # to these rooms.
        #
        # By default, any room aliases included in this list will be created
        # as a publicly joinable room when the first user registers for the
        # homeserver. This behaviour can be customised with the settings below.
        # If the room already exists, make certain it is a publicly joinable
        # room. The join rule of the room must be set to 'public'.
        #
        #auto_join_rooms:
        #  - "#example:example.com"

        # Where auto_join_rooms are specified, setting this flag ensures that the
        # the rooms exist by creating them when the first user on the
        # homeserver registers.
        #
        # By default the auto-created rooms are publicly joinable from any federated
        # server. Use the autocreate_auto_join_rooms_federated and
        # autocreate_auto_join_room_preset settings below to customise this behaviour.
        #
        # Setting to false means that if the rooms are not manually created,
        # users cannot be auto-joined since they do not exist.
        #
        # Defaults to true. Uncomment the following line to disable automatically
        # creating auto-join rooms.
        #
        #autocreate_auto_join_rooms: false

        # Whether the auto_join_rooms that are auto-created are available via
        # federation. Only has an effect if autocreate_auto_join_rooms is true.
        #
        # Note that whether a room is federated cannot be modified after
        # creation.
        #
        # Defaults to true: the room will be joinable from other servers.
        # Uncomment the following to prevent users from other homeservers from
        # joining these rooms.
        #
        #autocreate_auto_join_rooms_federated: false

        # The room preset to use when auto-creating one of auto_join_rooms. Only has an
        # effect if autocreate_auto_join_rooms is true.
        #
        # This can be one of "public_chat", "private_chat", or "trusted_private_chat".
        # If a value of "private_chat" or "trusted_private_chat" is used then
        # auto_join_mxid_localpart must also be configured.
        #
        # Defaults to "public_chat", meaning that the room is joinable by anyone, including
        # federated servers if autocreate_auto_join_rooms_federated is true (the default).
        # Uncomment the following to require an invitation to join these rooms.
        #
        #autocreate_auto_join_room_preset: private_chat

        # The local part of the user id which is used to create auto_join_rooms if
        # autocreate_auto_join_rooms is true. If this is not provided then the
        # initial user account that registers will be used to create the rooms.
        #
        # The user id is also used to invite new users to any auto-join rooms which
        # are set to invite-only.
        #
        # It *must* be configured if autocreate_auto_join_room_preset is set to
        # "private_chat" or "trusted_private_chat".
        #
        # Note that this must be specified in order for new users to be correctly
        # invited to any auto-join rooms which have been set to invite-only (either
        # at the time of creation or subsequently).
        #
        # Note that, if the room already exists, this user must be joined and
        # have the appropriate permissions to invite new members.
        #
        #auto_join_mxid_localpart: system

        # When auto_join_rooms is specified, setting this flag to false prevents
        # guest accounts from being automatically joined to the rooms.
        #
        # Defaults to true.
        #
        #auto_join_rooms_for_guests: false

        # Whether to inhibit errors raised when registering a new account if the user ID
        # already exists. If turned on, that requests to /register/available will always
        # show a user ID as available, and Synapse won't raise an error when starting
        # a registration with a user ID that already exists. However, Synapse will still
        # raise an error if the registration completes and the username conflicts.
        #
        # Defaults to false.
        #
        #inhibit_user_in_use_error: true
        """
            % locals()
        )

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        reg_group = parser.add_argument_group("registration")
        reg_group.add_argument(
            "--enable-registration",
            action="store_true",
            default=None,
            help="Enable registration for new users.",
        )

    def read_arguments(self, args: argparse.Namespace) -> None:
        if args.enable_registration is not None:
            self.enable_registration = strtobool(str(args.enable_registration))
