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

import os
from ._base import Config, ConfigError
import syutil.crypto.signing_key


class KeyConfig(Config):

    def __init__(self, args):
        super(KeyConfig, self).__init__(args)
        self.signing_key = self.read_signing_key(args.signing_key_path)
        self.old_signing_keys = self.read_old_signing_keys(
            args.old_signing_key_path
        )
        self.key_refresh_interval = args.key_refresh_interval

    @classmethod
    def add_arguments(cls, parser):
        super(KeyConfig, cls).add_arguments(parser)
        key_group = parser.add_argument_group("keys")
        key_group.add_argument("--signing-key-path",
                               help="The signing key to sign messages with")
        key_group.add_argument("--old-signing-key-path",
                               help="The keys that the server used to sign"
                                    " sign messages with but won't use"
                                    " to sign new messages. E.g. it has"
                                    " lost its private key")
        key_group.add_argument("--key-refresh-interval",
                               default=24 * 60 * 60 * 1000,  # 1 Day
                               help="How long a key response is valid for."
                                    " Used to set the exipiry in /key/v2/."
                                    " Controls how frequently servers will"
                                    " query what keys are still valid")

    def read_signing_key(self, signing_key_path):
        signing_keys = self.read_file(signing_key_path, "signing_key")
        try:
            return syutil.crypto.signing_key.read_signing_keys(
                signing_keys.splitlines(True)
            )
        except Exception:
            raise ConfigError(
                "Error reading signing_key."
                " Try running again with --generate-config"
            )

    def read_old_signing_keys(self, old_signing_key_path):
        old_signing_keys = self.read_file(
            old_signing_key_path, "old_signing_key"
        )
        try:
            return syutil.crypto.signing_key.read_old_signing_keys(
                old_signing_keys.splitlines(True)
            )
        except Exception:
            raise ConfigError(
                "Error reading old signing keys."
            )

    @classmethod
    def generate_config(cls, args, config_dir_path):
        super(KeyConfig, cls).generate_config(args, config_dir_path)
        base_key_name = os.path.join(config_dir_path, args.server_name)

        args.pid_file = os.path.abspath(args.pid_file)

        if not args.signing_key_path:
            args.signing_key_path = base_key_name + ".signing.key"

        if not os.path.exists(args.signing_key_path):
            with open(args.signing_key_path, "w") as signing_key_file:
                syutil.crypto.signing_key.write_signing_keys(
                    signing_key_file,
                    (syutil.crypto.signing_key.generate_signing_key("auto"),),
                )
        else:
            signing_keys = cls.read_file(args.signing_key_path, "signing_key")
            if len(signing_keys.split("\n")[0].split()) == 1:
                # handle keys in the old format.
                key = syutil.crypto.signing_key.decode_signing_key_base64(
                    syutil.crypto.signing_key.NACL_ED25519,
                    "auto",
                    signing_keys.split("\n")[0]
                )
                with open(args.signing_key_path, "w") as signing_key_file:
                    syutil.crypto.signing_key.write_signing_keys(
                        signing_key_file,
                        (key,),
                    )

        if not args.old_signing_key_path:
            args.old_signing_key_path = base_key_name + ".old.signing.keys"

        if not os.path.exists(args.old_signing_key_path):
            with open(args.old_signing_key_path, "w"):
                pass
