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

from distutils.util import strtobool

from synapse.config._base import Config, ConfigError
from synapse.types import RoomAlias
from synapse.util.stringutils import random_string_with_symbols


class AccountValidityConfig(Config):
    def __init__(self, config, synapse_config):
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

        if self.renew_by_email_enabled and "public_baseurl" not in synapse_config:
            raise ConfigError("Can't send renewal emails without 'public_baseurl'")


class RegistrationConfig(Config):
    def read_config(self, config, **kwargs):
        self.enable_registration = bool(
            strtobool(str(config.get("enable_registration", False)))
        )
        if "disable_registration" in config:
            self.enable_registration = not bool(
                strtobool(str(config["disable_registration"]))
            )

        self.account_validity = AccountValidityConfig(
            config.get("account_validity", {}), config
        )

        self.registrations_require_3pid = config.get("registrations_require_3pid", [])
        self.allowed_local_3pids = config.get("allowed_local_3pids", [])
        self.enable_3pid_lookup = config.get("enable_3pid_lookup", True)
        self.registration_shared_secret = config.get("registration_shared_secret")

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)
        self.trusted_third_party_id_servers = config.get(
            "trusted_third_party_id_servers", ["matrix.org", "vector.im"]
        )
        self.default_identity_server = config.get("default_identity_server")
        self.allow_guest_access = config.get("allow_guest_access", False)

        self.invite_3pid_guest = self.allow_guest_access and config.get(
            "invite_3pid_guest", False
        )

        self.auto_join_rooms = config.get("auto_join_rooms", [])
        for room_alias in self.auto_join_rooms:
            if not RoomAlias.is_valid(room_alias):
                raise ConfigError("Invalid auto_join_rooms entry %s" % (room_alias,))
        self.autocreate_auto_join_rooms = config.get("autocreate_auto_join_rooms", True)

        self.disable_msisdn_registration = config.get(
            "disable_msisdn_registration", False
        )

    def generate_config_section(self, generate_secrets=False, **kwargs):
        if generate_secrets:
            registration_shared_secret = 'registration_shared_secret: "%s"' % (
                random_string_with_symbols(50),
            )
        else:
            registration_shared_secret = (
                "# registration_shared_secret: <PRIVATE STRING>"
            )

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
        # ``enabled`` defines whether the account validity feature is enabled. Defaults
        # to False.
        #
        # ``period`` allows setting the period after which an account is valid
        # after its registration. When renewing the account, its validity period
        # will be extended by this amount of time. This parameter is required when using
        # the account validity feature.
        #
        # ``renew_at`` is the amount of time before an account's expiry date at which
        # Synapse will send an email to the account's email address with a renewal link.
        # This needs the ``email`` and ``public_baseurl`` configuration sections to be
        # filled.
        #
        # ``renew_email_subject`` is the subject of the email sent out with the renewal
        # link. ``%%(app)s`` can be used as a placeholder for the ``app_name`` parameter
        # from the ``email`` section.
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
        #account_validity:
        #  enabled: True
        #  period: 6w
        #  renew_at: 1w
        #  renew_email_subject: "Renew your %%(app)s account"

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

        # The list of identity servers trusted to verify third party
        # identifiers by this server.
        #
        # Also defines the ID server which will be called when an account is
        # deactivated (one will be picked arbitrarily).
        #
        #trusted_third_party_id_servers:
        #  - matrix.org
        #  - vector.im

        # Users who register on this homeserver will automatically be joined
        # to these rooms
        #
        #auto_join_rooms:
        #  - "#example:example.com"

        # Where auto_join_rooms are specified, setting this flag ensures that the
        # the rooms exist by creating them when the first user on the
        # homeserver registers.
        # Setting to false means that if the rooms are not manually created,
        # users cannot be auto-joined since they do not exist.
        #
        #autocreate_auto_join_rooms: true
        """
            % locals()
        )

    def add_arguments(self, parser):
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
