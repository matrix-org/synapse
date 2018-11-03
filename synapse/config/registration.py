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


class RegistrationConfig(Config):

    def read_config(self, config):
        self.enable_registration = bool(
            strtobool(str(config["enable_registration"]))
        )
        if "disable_registration" in config:
            self.enable_registration = not bool(
                strtobool(str(config["disable_registration"]))
            )

        self.registrations_require_3pid = config.get("registrations_require_3pid", [])
        self.allowed_local_3pids = config.get("allowed_local_3pids", [])
        self.check_is_for_allowed_local_3pids = config.get(
            "check_is_for_allowed_local_3pids", None
        )
        self.allow_invited_3pids = config.get("allow_invited_3pids", False)

        self.disable_3pid_changes = config.get("disable_3pid_changes", False)

        self.registration_shared_secret = config.get("registration_shared_secret")
        self.register_mxid_from_3pid = config.get("register_mxid_from_3pid")

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)
        self.trusted_third_party_id_servers = config["trusted_third_party_id_servers"]
        self.allow_guest_access = config.get("allow_guest_access", False)

        self.invite_3pid_guest = (
            self.allow_guest_access and config.get("invite_3pid_guest", False)
        )

        self.auto_join_rooms = config.get("auto_join_rooms", [])
        for room_alias in self.auto_join_rooms:
            if not RoomAlias.is_valid(room_alias):
                raise ConfigError('Invalid auto_join_rooms entry %s' % (room_alias,))
        self.autocreate_auto_join_rooms = config.get("autocreate_auto_join_rooms", True)

        self.disable_set_displayname = config.get("disable_set_displayname", False)
        self.disable_set_avatar_url = config.get("disable_set_avatar_url", False)

        self.replicate_user_profiles_to = config.get("replicate_user_profiles_to", [])
        if not isinstance(self.replicate_user_profiles_to, list):
            self.replicate_user_profiles_to = [self.replicate_user_profiles_to, ]

    def default_config(self, **kwargs):
        registration_shared_secret = random_string_with_symbols(50)

        return """\
        ## Registration ##

        # Enable registration for new users.
        enable_registration: False

        # The user must provide all of the below types of 3PID when registering.
        #
        # registrations_require_3pid:
        #     - email
        #     - msisdn

        # Derive the user's matrix ID from a type of 3PID used when registering.
        # This overrides any matrix ID the user proposes when calling /register
        # The 3PID type should be present in registrations_require_3pid to avoid
        # users failing to register if they don't specify the right kind of 3pid.
        #
        # register_mxid_from_3pid: email

        # Mandate that users are only allowed to associate certain formats of
        # 3PIDs with accounts on this server.
        #
        # Use an Identity Server to establish which 3PIDs are allowed to register?
        # Overrides allowed_local_3pids below.
        # check_is_for_allowed_local_3pids: matrix.org
        #
        # If you are using an IS you can also check whether that IS registers
        # pending invites for the given 3PID (and then allow it to sign up on
        # the platform):
        #
        # allow_invited_3pids: False
        #
        # allowed_local_3pids:
        #     - medium: email
        #       pattern: ".*@matrix\\.org"
        #     - medium: email
        #       pattern: ".*@vector\\.im"
        #     - medium: msisdn
        #       pattern: "\\+44"

        # If true, stop users from trying to change the 3PIDs associated with
        # their accounts.
        #
        # disable_3pid_changes: False

        # If set, allows registration by anyone who also has the shared
        # secret, even if registration is otherwise disabled.
        registration_shared_secret: "%(registration_shared_secret)s"

        # Set the number of bcrypt rounds used to generate password hash.
        # Larger numbers increase the work factor needed to generate the hash.
        # The default number is 12 (which equates to 2^12 rounds).
        # N.B. that increasing this will exponentially increase the time required
        # to register or login - e.g. 24 => 2^24 rounds which will take >20 mins.
        bcrypt_rounds: 12

        # Allows users to register as guests without a password/email/etc, and
        # participate in rooms hosted on this server which have been made
        # accessible to anonymous users.
        allow_guest_access: False

        # The list of identity servers trusted to verify third party
        # identifiers by this server.
        trusted_third_party_id_servers:
            - matrix.org
            - vector.im
            - riot.im

        # If enabled, user IDs, display names and avatar URLs will be replicated
        # to this server whenever they change.
        # This is an experimental API currently implemented by sydent to support
        # cross-homeserver user directories.
        # replicate_user_profiles_to: example.com

        # If enabled, don't let users set their own display names/avatars
        # other than for the very first time (unless they are a server admin).
        # Useful when provisioning users based on the contents of a 3rd party
        # directory and to avoid ambiguities.
        #
        # disable_set_displayname: False
        # disable_set_avatar_url: False

        # Users who register on this homeserver will automatically be joined
        # to these rooms
        #auto_join_rooms:
        #    - "#example:example.com"

        # Where auto_join_rooms are specified, setting this flag ensures that the
        # the rooms exist by creating them when the first user on the
        # homeserver registers.
        # Setting to false means that if the rooms are not manually created,
        # users cannot be auto-joined since they do not exist.
        autocreate_auto_join_rooms: true
        """ % locals()

    def add_arguments(self, parser):
        reg_group = parser.add_argument_group("registration")
        reg_group.add_argument(
            "--enable-registration", action="store_true", default=None,
            help="Enable registration for new users."
        )

    def read_arguments(self, args):
        if args.enable_registration is not None:
            self.enable_registration = bool(
                strtobool(str(args.enable_registration))
            )
