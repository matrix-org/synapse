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

from ._base import Config

from synapse.util.stringutils import random_string_with_symbols

from distutils.util import strtobool


class RegistrationConfig(Config):

    def read_config(self, config):
        self.enable_registration = bool(
            strtobool(str(config["enable_registration"]))
        )
        if "disable_registration" in config:
            self.enable_registration = not bool(
                strtobool(str(config["disable_registration"]))
            )

        self.registration_shared_secret = config.get("registration_shared_secret")

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)
        self.trusted_third_party_id_servers = config["trusted_third_party_id_servers"]
        self.allow_guest_access = config.get("allow_guest_access", False)

        self.invite_3pid_guest = (
            self.allow_guest_access and config.get("invite_3pid_guest", False)
        )

    def default_config(self, **kwargs):
        registration_shared_secret = random_string_with_symbols(50)

        return """\
        ## Registration ##

        # Enable registration for new users.
        enable_registration: False

        # If set, allows registration by anyone who also has the shared
        # secret, even if registration is otherwise disabled.
        registration_shared_secret: "%(registration_shared_secret)s"

        # Set the number of bcrypt rounds used to generate password hash.
        # Larger numbers increase the work factor needed to generate the hash.
        # The default number of rounds is 12.
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
