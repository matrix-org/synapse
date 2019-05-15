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

import hashlib
import logging
import os

from signedjson.key import (
    NACL_ED25519,
    decode_signing_key_base64,
    decode_verify_key_bytes,
    generate_signing_key,
    is_signing_algorithm_supported,
    read_signing_keys,
    write_signing_keys,
)
from unpaddedbase64 import decode_base64

from synapse.util.stringutils import random_string, random_string_with_symbols

from ._base import Config, ConfigError

logger = logging.getLogger(__name__)


class KeyConfig(Config):

    def read_config(self, config):
        # the signing key can be specified inline or in a separate file
        if "signing_key" in config:
            self.signing_key = read_signing_keys([config["signing_key"]])
        else:
            self.signing_key_path = config["signing_key_path"]
            self.signing_key = self.read_signing_key(self.signing_key_path)

        self.old_signing_keys = self.read_old_signing_keys(
            config.get("old_signing_keys", {})
        )
        self.key_refresh_interval = self.parse_duration(
            config.get("key_refresh_interval", "1d"),
        )
        self.perspectives = self.read_perspectives(
            config.get("perspectives", {}).get("servers", {
                "matrix.org": {"verify_keys": {
                    "ed25519:auto": {
                        "key": "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw",
                    }
                }}
            })
        )

        self.macaroon_secret_key = config.get(
            "macaroon_secret_key", self.registration_shared_secret
        )

        if not self.macaroon_secret_key:
            # Unfortunately, there are people out there that don't have this
            # set. Lets just be "nice" and derive one from their secret key.
            logger.warn("Config is missing macaroon_secret_key")
            seed = bytes(self.signing_key[0])
            self.macaroon_secret_key = hashlib.sha256(seed).digest()

        self.expire_access_token = config.get("expire_access_token", False)

        # a secret which is used to calculate HMACs for form values, to stop
        # falsification of values
        self.form_secret = config.get("form_secret", None)

    def default_config(self, config_dir_path, server_name, generate_secrets=False,
                       **kwargs):
        base_key_name = os.path.join(config_dir_path, server_name)

        if generate_secrets:
            macaroon_secret_key = 'macaroon_secret_key: "%s"' % (
                random_string_with_symbols(50),
            )
            form_secret = 'form_secret: "%s"' % random_string_with_symbols(50)
        else:
            macaroon_secret_key = "# macaroon_secret_key: <PRIVATE STRING>"
            form_secret = "# form_secret: <PRIVATE STRING>"

        return """\
        # a secret which is used to sign access tokens. If none is specified,
        # the registration_shared_secret is used, if one is given; otherwise,
        # a secret key is derived from the signing key.
        #
        %(macaroon_secret_key)s

        # Used to enable access token expiration.
        #
        #expire_access_token: False

        # a secret which is used to calculate HMACs for form values, to stop
        # falsification of values. Must be specified for the User Consent
        # forms to work.
        #
        %(form_secret)s

        ## Signing Keys ##

        # Path to the signing key to sign messages with
        #
        signing_key_path: "%(base_key_name)s.signing.key"

        # The keys that the server used to sign messages with but won't use
        # to sign new messages. E.g. it has lost its private key
        #
        #old_signing_keys:
        #  "ed25519:auto":
        #    # Base64 encoded public key
        #    key: "The public part of your old signing key."
        #    # Millisecond POSIX timestamp when the key expired.
        #    expired_ts: 123456789123

        # How long key response published by this server is valid for.
        # Used to set the valid_until_ts in /key/v2 APIs.
        # Determines how quickly servers will query to check which keys
        # are still valid.
        #
        #key_refresh_interval: 1d

        # The trusted servers to download signing keys from.
        #
        #perspectives:
        #  servers:
        #    "matrix.org":
        #      verify_keys:
        #        "ed25519:auto":
        #          key: "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw"
        """ % locals()

    def read_perspectives(self, perspectives_servers):
        servers = {}
        for server_name, server_config in perspectives_servers.items():
            for key_id, key_data in server_config["verify_keys"].items():
                if is_signing_algorithm_supported(key_id):
                    key_base64 = key_data["key"]
                    key_bytes = decode_base64(key_base64)
                    verify_key = decode_verify_key_bytes(key_id, key_bytes)
                    servers.setdefault(server_name, {})[key_id] = verify_key
        return servers

    def read_signing_key(self, signing_key_path):
        signing_keys = self.read_file(signing_key_path, "signing_key")
        try:
            return read_signing_keys(signing_keys.splitlines(True))
        except Exception as e:
            raise ConfigError(
                "Error reading signing_key: %s" % (str(e))
            )

    def read_old_signing_keys(self, old_signing_keys):
        keys = {}
        for key_id, key_data in old_signing_keys.items():
            if is_signing_algorithm_supported(key_id):
                key_base64 = key_data["key"]
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_key.expired_ts = key_data["expired_ts"]
                keys[key_id] = verify_key
            else:
                raise ConfigError(
                    "Unsupported signing algorithm for old key: %r" % (key_id,)
                )
        return keys

    def generate_files(self, config):
        signing_key_path = config["signing_key_path"]

        if not self.path_exists(signing_key_path):
            with open(signing_key_path, "w") as signing_key_file:
                key_id = "a_" + random_string(4)
                write_signing_keys(
                    signing_key_file, (generate_signing_key(key_id),),
                )
        else:
            signing_keys = self.read_file(signing_key_path, "signing_key")
            if len(signing_keys.split("\n")[0].split()) == 1:
                # handle keys in the old format.
                key_id = "a_" + random_string(4)
                key = decode_signing_key_base64(
                    NACL_ED25519, key_id, signing_keys.split("\n")[0]
                )
                with open(signing_key_path, "w") as signing_key_file:
                    write_signing_keys(
                        signing_key_file, (key,),
                    )
