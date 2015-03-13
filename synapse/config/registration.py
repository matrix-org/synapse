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


class RegistrationConfig(Config):

    def __init__(self, args):
        super(RegistrationConfig, self).__init__(args)
        self.disable_registration = args.disable_registration

    @classmethod
    def add_arguments(cls, parser):
        super(RegistrationConfig, cls).add_arguments(parser)
        reg_group = parser.add_argument_group("registration")
        reg_group.add_argument(
            "--disable-registration",
            action='store_true',
            help="Disable registration of new users."
        )

    @classmethod
    def generate_config(cls, args, config_dir_path):
        args.disable_registration = True
