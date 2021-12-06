# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.constants import RoomCreationPreset
from synapse.config._base import Config, ConfigError
from synapse.types import RoomAlias, UserID
from synapse.util.stringutils import random_string_with_symbols, strtobool


class RegistrationConfig(Config):
    section = "registration"

    def read_config(self, config, **kwargs):
        self.enable_registration = strtobool(
            str(config.get("enable_registration", False))
        )
        if "disable_registration" in config:
            self.enable_registration = not strtobool(
                str(config["disable_registration"])
            )

        self.registrations_require_3pid = config.get("registrations_require_3pid", [])
        self.allowed_local_3pids = config.get("allowed_local_3pids", [])
        self.check_is_for_allowed_local_3pids = config.get(
            "check_is_for_allowed_local_3pids", None
        )
        self.allow_invited_3pids = config.get("allow_invited_3pids", False)

        self.disable_3pid_changes = config.get("disable_3pid_changes", False)

        self.enable_3pid_lookup = config.get("enable_3pid_lookup", True)
        self.registration_requires_token = config.get(
            "registration_requires_token", False
        )
        self.registration_shared_secret = config.get("registration_shared_secret")
        self.register_mxid_from_3pid = config.get("register_mxid_from_3pid")
        self.register_just_use_email_for_display_name = config.get(
            "register_just_use_email_for_display_name", False
        )

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)
        self.trusted_third_party_id_servers = config.get(
            "trusted_third_party_id_servers", ["matrix.org", "vector.im"]
        )
        account_threepid_delegates = config.get("account_threepid_delegates") or {}
        self.account_threepid_delegate_email = account_threepid_delegates.get("email")
        if (
            self.account_threepid_delegate_email
            and not self.account_threepid_delegate_email.startswith("http")
        ):
            raise ConfigError(
                "account_threepid_delegates.email must begin with http:// or https://"
            )
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

        self.replicate_user_profiles_to = config.get("replicate_user_profiles_to", [])
        if not isinstance(self.replicate_user_profiles_to, list):
            self.replicate_user_profiles_to = [self.replicate_user_profiles_to]

        self.rewrite_identity_server_urls = (
            config.get("rewrite_identity_server_urls") or {}
        )

        self.disable_msisdn_registration = config.get(
            "disable_msisdn_registration", False
        )

        session_lifetime = config.get("session_lifetime")
        if session_lifetime is not None:
            session_lifetime = self.parse_duration(session_lifetime)
        self.session_lifetime = session_lifetime

        # The `access_token_lifetime` applies for tokens that can be renewed
        # using a refresh token, as per MSC2918. If it is `None`, the refresh
        # token mechanism is disabled.
        #
        # Since it is incompatible with the `session_lifetime` mechanism, it is set to
        # `None` by default if a `session_lifetime` is set.
        access_token_lifetime = config.get(
            "access_token_lifetime", "5m" if session_lifetime is None else None
        )
        if access_token_lifetime is not None:
            access_token_lifetime = self.parse_duration(access_token_lifetime)
        self.access_token_lifetime = access_token_lifetime

        if session_lifetime is not None and access_token_lifetime is not None:
            raise ConfigError(
                "The refresh token mechanism is incompatible with the "
                "`session_lifetime` option. Consider disabling the "
                "`session_lifetime` option or disabling the refresh token "
                "mechanism by removing the `access_token_lifetime` option."
            )

        # The fallback template used for authenticating using a registration token
        self.registration_token_template = self.read_template("registration_token.html")

        # The success template used during fallback auth.
        self.fallback_success_template = self.read_template("auth_success.html")

        self.bind_new_user_emails_to_sydent = config.get(
            "bind_new_user_emails_to_sydent"
        )

        if self.bind_new_user_emails_to_sydent:
            if not isinstance(
                self.bind_new_user_emails_to_sydent, str
            ) or not self.bind_new_user_emails_to_sydent.startswith("http"):
                raise ConfigError(
                    "Option bind_new_user_emails_to_sydent has invalid value"
                )

            # Remove trailing slashes
            self.bind_new_user_emails_to_sydent = (
                self.bind_new_user_emails_to_sydent.strip("/")
            )

    def generate_config_section(self, generate_secrets=False, **kwargs):
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

        # Enable registration for new users.
        #
        #enable_registration: false

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

        # The user must provide all of the below types of 3PID when registering.
        #
        #registrations_require_3pid:
        #  - email
        #  - msisdn

        # Explicitly disable asking for MSISDNs from the registration
        # flow (overrides registrations_require_3pid if MSISDNs are set as required)
        #
        #disable_msisdn_registration: true

        # Derive the user's matrix ID from a type of 3PID used when registering.
        # This overrides any matrix ID the user proposes when calling /register
        # The 3PID type should be present in registrations_require_3pid to avoid
        # users failing to register if they don't specify the right kind of 3pid.
        #
        #register_mxid_from_3pid: email

        # Uncomment to set the display name of new users to their email address,
        # rather than using the default heuristic.
        #
        #register_just_use_email_for_display_name: true

        # Mandate that users are only allowed to associate certain formats of
        # 3PIDs with accounts on this server.
        #
        # Use an Identity Server to establish which 3PIDs are allowed to register?
        # Overrides allowed_local_3pids below.
        #
        #check_is_for_allowed_local_3pids: matrix.org
        #
        # If you are using an IS you can also check whether that IS registers
        # pending invites for the given 3PID (and then allow it to sign up on
        # the platform):
        #
        #allow_invited_3pids: false
        #
        #allowed_local_3pids:
        #  - medium: email
        #    pattern: '^[^@]+@matrix\\.org$'
        #  - medium: email
        #    pattern: '^[^@]+@vector\\.im$'
        #  - medium: msisdn
        #    pattern: '\\+44'

        # If true, stop users from trying to change the 3PIDs associated with
        # their accounts.
        #
        #disable_3pid_changes: false

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

        # If enabled, user IDs, display names and avatar URLs will be replicated
        # to this server whenever they change.
        # This is an experimental API currently implemented by sydent to support
        # cross-homeserver user directories.
        #
        #replicate_user_profiles_to: example.com

        # If enabled, don't let users set their own display names/avatars
        # other than for the very first time (unless they are a server admin).
        # Useful when provisioning users based on the contents of a 3rd party
        # directory and to avoid ambiguities.
        #
        #disable_set_displayname: false
        #disable_set_avatar_url: false

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

        # Rewrite identity server URLs with a map from one URL to another. Applies to URLs
        # provided by clients (which have https:// prepended) and those specified
        # in `account_threepid_delegates`. URLs should not feature a trailing slash.
        #
        #rewrite_identity_server_urls:
        #   "https://somewhere.example.com": "https://somewhereelse.example.com"

        # When a user registers an account with an email address, it can be useful to
        # bind that email address to their mxid on an identity server. Typically, this
        # requires the user to validate their email address with the identity server.
        # However if Synapse itself is handling email validation on registration, the
        # user ends up needing to validate their email twice, which leads to poor UX.
        #
        # It is possible to force Sydent, one identity server implementation, to bind
        # threepids using its internal, unauthenticated bind API:
        # https://github.com/matrix-org/sydent/#internal-bind-and-unbind-api
        #
        # Configure the address of a Sydent server here to have Synapse attempt
        # to automatically bind users' emails following registration. The
        # internal bind API must be reachable from Synapse, but should NOT be
        # exposed to any third party, as it allows the creation of bindings
        # without validation.
        #
        #bind_new_user_emails_to_sydent: https://example.com:8091
        """
            % locals()
        )

    @staticmethod
    def add_arguments(parser):
        reg_group = parser.add_argument_group("registration")
        reg_group.add_argument(
            "--enable-registration",
            action="store_true",
            default=None,
            help="Enable registration for new users.",
        )

    def read_arguments(self, args):
        if args.enable_registration is not None:
            self.enable_registration = strtobool(str(args.enable_registration))
