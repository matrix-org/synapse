# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
        self.disable_registration = not bool(
            strtobool(str(config["enable_registration"]))
        )
        if "disable_registration" in config:
            self.disable_registration = bool(
                strtobool(str(config["disable_registration"]))
            )

        self.registration_shared_secret = config.get("registration_shared_secret")

    def default_config(self, config_dir, server_name):
        registration_shared_secret = random_string_with_symbols(50)
        return """\
        ## Registration ##

        # Enable registration for new users.
        enable_registration: True

        # If set, allows registration by anyone who also has the shared
        # secret, even if registration is otherwise disabled.
        registration_shared_secret: "%(registration_shared_secret)s"
        """ % locals()

    def add_arguments(self, parser):
        reg_group = parser.add_argument_group("registration")
        reg_group.add_argument(
            "--enable-registration", action="store_true", default=None,
            help="Enable registration for new users."
        )

    def read_arguments(self, args):
        if args.enable_registration is not None:
            self.disable_registration = not bool(
                strtobool(str(args.enable_registration))
            )
