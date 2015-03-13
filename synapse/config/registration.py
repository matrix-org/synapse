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


class RegistrationConfig(Config):

    def __init__(self, args):
        super(RegistrationConfig, self).__init__(args)
        self.disable_registration = args.disable_registration
        self.registration_shared_secret = args.registration_shared_secret

    @classmethod
    def add_arguments(cls, parser):
        super(RegistrationConfig, cls).add_arguments(parser)
        reg_group = parser.add_argument_group("registration")

        reg_group.add_argument(
            "--disable-registration",
            action='store_const',
            const=True,
            help="Disable registration of new users.",
        )
        reg_group.add_argument(
            "--registration-shared-secret", type=str,
            help="If set, allows registration by anyone who also has the shared"
                 " secret, even if registration is otherwise disabled.",
        )

    @classmethod
    def generate_config(cls, args, config_dir_path):
        if args.disable_registration is None:
            args.disable_registration = True

        if args.registration_shared_secret is None:
            args.registration_shared_secret= random_string_with_symbols(50)
