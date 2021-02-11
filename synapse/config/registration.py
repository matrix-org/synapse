# -*- coding: utf-8 -*-
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

import os

import pkg_resources

from synapse.api.constants import RoomCreationPreset
from synapse.config._base import Config, ConfigError
from synapse.types import RoomAlias, UserID
from synapse.util.stringutils import random_string_with_symbols, strtobool


class AccountValidityConfig(Config):
    section = "accountvalidity"

    def __init__(self, config, synapse_config):
        if config is None:
            return
        super().__init__()
        self.enabled = config.get("enabled", False)
        self.renew_by_email_enabled = "renew_at" in config

        if self.enabled:
            if "period" in config:
                self.period = self.parse_duration(config["period"])
            else:
                raise ConfigError("'period' is required when using account validity")

            if "renew_at" in config:
                self.renew_at = self.parse_duration(config["renew_at"])

            if "renew_email_subject" in config:
                self.renew_email_subject = config["renew_email_subject"]
            else:
                self.renew_email_subject = "Renew your %(app)s account"

            self.startup_job_max_delta = self.period * 10.0 / 100.0

        if self.renew_by_email_enabled:
            if "public_baseurl" not in synapse_config:
                raise ConfigError("Can't send renewal emails without 'public_baseurl'")

        template_dir = config.get("template_dir")

        if not template_dir:
            template_dir = pkg_resources.resource_filename("synapse", "res/templates")

        if "account_renewed_html_path" in config:
            file_path = os.path.join(template_dir, config["account_renewed_html_path"])

            self.account_renewed_html_content = self.read_file(
                file_path, "account_validity.account_renewed_html_path"
            )
        else:
            self.account_renewed_html_content = (
                "<html><body>Your account has been successfully renewed.</body><html>"
            )

        if "invalid_token_html_path" in config:
            file_path = os.path.join(template_dir, config["invalid_token_html_path"])

            self.invalid_token_html_content = self.read_file(
                file_path, "account_validity.invalid_token_html_path"
            )
        else:
            self.invalid_token_html_content = (
                "<html><body>Invalid renewal token.</body><html>"
            )


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

        self.account_validity = AccountValidityConfig(
            config.get("account_validity") or {}, config
        )

        self.registrations_require_3pid = config.get("registrations_require_3pid", [])
        self.allowed_local_3pids = config.get("allowed_local_3pids", [])
        self.enable_3pid_lookup = config.get("enable_3pid_lookup", True)
        self.registration_shared_secret = config.get("registration_shared_secret")

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)
        self.trusted_third_party_id_servers = config.get(
            "trusted_third_party_id_servers", ["matrix.org", "vector.im"]
        )
        account_threepid_delegates = config.get("account_threepid_delegates") or {}
        self.account_threepid_delegate_email = account_threepid_delegates.get("email")
        self.account_threepid_delegate_msisdn = account_threepid_delegates.get("msisdn")
        if self.account_threepid_delegate_msisdn and not self.public_baseurl:
            raise ConfigError(
                "The configuration option `public_baseurl` is required if "
                "`account_threepid_delegate.msisdn` is set, such that "
                "clients know where to submit validation tokens to. Please "
                "configure `public_baseurl`."
            )

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
                mxid_localpart, self.server_name
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

        # The success template used during fallback auth.
        self.fallback_success_template = self.read_template("auth_success.html")

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

        # Optional account validity configuration. This allows for accounts to be denied
        # any request after a given period.
        #
        # Once this feature is enabled, Synapse will look for registered users without an
        # expiration date at startup and will add one to every account it found using the
        # current settings at that time.
        # This means that, if a validity period is set, and Synapse is restarted (it will
        # then derive an expiration date from the current validity period), and some time
        # after that the validity period changes and Synapse is restarted, the users'
        # expiration dates won't be updated unless their account is manually renewed. This
        # date will be randomly selected within a range [now + period - d ; now + period],
        # where d is equal to 10%% of the validity period.
        #
        account_validity:
          # The account validity feature is disabled by default. Uncomment the
          # following line to enable it.
          #
          #enabled: true

          # The period after which an account is valid after its registration. When
          # renewing the account, its validity period will be extended by this amount
          # of time. This parameter is required when using the account validity
          # feature.
          #
          #period: 6w

          # The amount of time before an account's expiry date at which Synapse will
          # send an email to the account's email address with a renewal link. By
          # default, no such emails are sent.
          #
          # If you enable this setting, you will also need to fill out the 'email' and
          # 'public_baseurl' configuration sections.
          #
          #renew_at: 1w

          # The subject of the email sent out with the renewal link. '%%(app)s' can be
          # used as a placeholder for the 'app_name' parameter from the 'email'
          # section.
          #
          # Note that the placeholder must be written '%%(app)s', including the
          # trailing 's'.
          #
          # If this is not set, a default value is used.
          #
          #renew_email_subject: "Renew your %%(app)s account"

          # Directory in which Synapse will try to find templates for the HTML files to
          # serve to the user when trying to renew an account. If not set, default
          # templates from within the Synapse package will be used.
          #
          #template_dir: "res/templates"

          # File within 'template_dir' giving the HTML to be displayed to the user after
          # they successfully renewed their account. If not set, default text is used.
          #
          #account_renewed_html_path: "account_renewed.html"

          # File within 'template_dir' giving the HTML to be displayed when the user
          # tries to renew an account with an invalid renewal token. If not set,
          # default text is used.
          #
          #invalid_token_html_path: "invalid_token.html"

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

        # Mandate that users are only allowed to associate certain formats of
        # 3PIDs with accounts on this server.
        #
        #allowed_local_3pids:
        #  - medium: email
        #    pattern: '.*@matrix\\.org'
        #  - medium: email
        #    pattern: '.*@vector\\.im'
        #  - medium: msisdn
        #    pattern: '\\+44'

        # Enable 3PIDs lookup requests to identity servers from this server.
        #
        #enable_3pid_lookup: true

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
        # This setting is ignored unless public_baseurl is also set.)
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
        # If a delegate is specified, the config option public_baseurl must also be filled out.
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
            self.enable_registration = bool(strtobool(str(args.enable_registration)))
