# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional

import attr
import jsonschema
from signedjson.key import (
    NACL_ED25519,
    SigningKey,
    VerifyKey,
    decode_signing_key_base64,
    decode_verify_key_bytes,
    generate_signing_key,
    is_signing_algorithm_supported,
    read_signing_keys,
    write_signing_keys,
)
from unpaddedbase64 import decode_base64

from synapse.types import JsonDict
from synapse.util.stringutils import random_string, random_string_with_symbols

from ._base import Config, ConfigError

if TYPE_CHECKING:
    from signedjson.key import VerifyKeyWithExpiry

INSECURE_NOTARY_ERROR = """\
Your server is configured to accept key server responses without signature
validation or TLS certificate validation. This is likely to be very insecure. If
you are *sure* you want to do this, set 'accept_keys_insecurely' on the
keyserver configuration."""

RELYING_ON_MATRIX_KEY_ERROR = """\
Your server is configured to accept key server responses without TLS certificate
validation, and which are only signed by the old (possibly compromised)
matrix.org signing key 'ed25519:auto'. This likely isn't what you want to do,
and you should enable 'federation_verify_certificates' in your configuration.

If you are *sure* you want to do this, set 'accept_keys_insecurely' on the
trusted_key_server configuration."""

TRUSTED_KEY_SERVER_NOT_CONFIGURED_WARN = """\
Synapse requires that a list of trusted key servers are specified in order to
provide signing keys for other servers in the federation.

This homeserver does not have a trusted key server configured in
homeserver.yaml and will fall back to the default of 'matrix.org'.

Trusted key servers should be long-lived and stable which makes matrix.org a
good choice for many admins, but some admins may wish to choose another. To
suppress this warning, the admin should set 'trusted_key_servers' in
homeserver.yaml to their desired key server and 'suppress_key_server_warning'
to 'true'.

In a future release the software-defined default will be removed entirely and
the trusted key server will be defined exclusively by the value of
'trusted_key_servers'.
--------------------------------------------------------------------------------"""

TRUSTED_KEY_SERVER_CONFIGURED_AS_M_ORG_WARN = """\
This server is configured to use 'matrix.org' as its trusted key server via the
'trusted_key_servers' config option. 'matrix.org' is a good choice for a key
server since it is long-lived, stable and trusted. However, some admins may
wish to use another server for this purpose.

To suppress this warning and continue using 'matrix.org', admins should set
'suppress_key_server_warning' to 'true' in homeserver.yaml.
--------------------------------------------------------------------------------"""

logger = logging.getLogger(__name__)


@attr.s(slots=True, auto_attribs=True)
class TrustedKeyServer:
    # name of the server.
    server_name: str

    # map from key id to key object, or None to disable signature verification.
    verify_keys: Optional[Dict[str, VerifyKey]] = None


class KeyConfig(Config):
    section = "key"

    def read_config(
        self, config: JsonDict, config_dir_path: str, **kwargs: Any
    ) -> None:
        # the signing key can be specified inline or in a separate file
        if "signing_key" in config:
            self.signing_key = read_signing_keys([config["signing_key"]])
        else:
            assert config_dir_path is not None
            signing_key_path = config.get("signing_key_path")
            if signing_key_path is None:
                signing_key_path = os.path.join(
                    config_dir_path, config["server_name"] + ".signing.key"
                )

            self.signing_key = self.read_signing_keys(signing_key_path, "signing_key")

        self.old_signing_keys = self.read_old_signing_keys(
            config.get("old_signing_keys")
        )
        self.key_refresh_interval = self.parse_duration(
            config.get("key_refresh_interval", "1d")
        )

        suppress_key_server_warning = config.get("suppress_key_server_warning", False)
        key_server_signing_keys_path = config.get("key_server_signing_keys_path")
        if key_server_signing_keys_path:
            self.key_server_signing_keys = self.read_signing_keys(
                key_server_signing_keys_path, "key_server_signing_keys_path"
            )
        else:
            self.key_server_signing_keys = list(self.signing_key)

        # if neither trusted_key_servers nor perspectives are given, use the default.
        if "perspectives" not in config and "trusted_key_servers" not in config:
            logger.warning(TRUSTED_KEY_SERVER_NOT_CONFIGURED_WARN)
            key_servers = [{"server_name": "matrix.org"}]
        else:
            key_servers = config.get("trusted_key_servers", [])

            if not isinstance(key_servers, list):
                raise ConfigError(
                    "trusted_key_servers, if given, must be a list, not a %s"
                    % (type(key_servers).__name__,)
                )

            # merge the 'perspectives' config into the 'trusted_key_servers' config.
            key_servers.extend(_perspectives_to_key_servers(config))

            if not suppress_key_server_warning and "matrix.org" in (
                s["server_name"] for s in key_servers
            ):
                logger.warning(TRUSTED_KEY_SERVER_CONFIGURED_AS_M_ORG_WARN)

        # list of TrustedKeyServer objects
        self.key_servers = list(
            _parse_key_servers(
                key_servers, self.root.tls.federation_verify_certificates
            )
        )

        macaroon_secret_key: Optional[str] = config.get(
            "macaroon_secret_key", self.root.registration.registration_shared_secret
        )

        if not macaroon_secret_key:
            # Unfortunately, there are people out there that don't have this
            # set. Lets just be "nice" and derive one from their secret key.
            logger.warning("Config is missing macaroon_secret_key")
            seed = bytes(self.signing_key[0])
            self.macaroon_secret_key = hashlib.sha256(seed).digest()
        else:
            self.macaroon_secret_key = macaroon_secret_key.encode("utf-8")

        # a secret which is used to calculate HMACs for form values, to stop
        # falsification of values
        self.form_secret = config.get("form_secret", None)

    def generate_config_section(
        self,
        config_dir_path: str,
        server_name: str,
        generate_secrets: bool = False,
        **kwargs: Any,
    ) -> str:
        base_key_name = os.path.join(config_dir_path, server_name)
        macaroon_secret_key = ""
        form_secret = ""

        if generate_secrets:
            macaroon_secret_key = 'macaroon_secret_key: "%s"' % (
                random_string_with_symbols(50),
            )
            form_secret = 'form_secret: "%s"' % random_string_with_symbols(50)

        return (
            """\
        %(macaroon_secret_key)s
        %(form_secret)s
        signing_key_path: "%(base_key_name)s.signing.key"
        trusted_key_servers:
          - server_name: "matrix.org"
        """
            % locals()
        )

    def read_signing_keys(self, signing_key_path: str, name: str) -> List[SigningKey]:
        """Read the signing keys in the given path.

        Args:
            signing_key_path
            name: Associated config key name

        Returns:
            The signing keys read from the given path.
        """

        signing_keys = self.read_file(signing_key_path, name)
        try:
            return read_signing_keys(signing_keys.splitlines(True))
        except Exception as e:
            raise ConfigError("Error reading %s: %s" % (name, str(e)))

    def read_old_signing_keys(
        self, old_signing_keys: Optional[JsonDict]
    ) -> Dict[str, "VerifyKeyWithExpiry"]:
        if old_signing_keys is None:
            return {}
        keys = {}
        for key_id, key_data in old_signing_keys.items():
            if is_signing_algorithm_supported(key_id):
                key_base64 = key_data["key"]
                key_bytes = decode_base64(key_base64)
                verify_key: "VerifyKeyWithExpiry" = decode_verify_key_bytes(key_id, key_bytes)  # type: ignore[assignment]
                verify_key.expired = key_data["expired_ts"]
                keys[key_id] = verify_key
            else:
                raise ConfigError(
                    "Unsupported signing algorithm for old key: %r" % (key_id,)
                )
        return keys

    def generate_files(self, config: Dict[str, Any], config_dir_path: str) -> None:
        if "signing_key" in config:
            return

        signing_key_path = config.get("signing_key_path")
        if signing_key_path is None:
            signing_key_path = os.path.join(
                config_dir_path, config["server_name"] + ".signing.key"
            )

        if not self.path_exists(signing_key_path):
            print("Generating signing key file %s" % (signing_key_path,))
            with open(signing_key_path, "w") as signing_key_file:
                key_id = "a_" + random_string(4)
                write_signing_keys(signing_key_file, (generate_signing_key(key_id),))
        else:
            signing_keys = self.read_file(signing_key_path, "signing_key")
            if len(signing_keys.split("\n")[0].split()) == 1:
                # handle keys in the old format.
                key_id = "a_" + random_string(4)
                key = decode_signing_key_base64(
                    NACL_ED25519, key_id, signing_keys.split("\n")[0]
                )
                with open(signing_key_path, "w") as signing_key_file:
                    write_signing_keys(signing_key_file, (key,))


def _perspectives_to_key_servers(config: JsonDict) -> Iterator[JsonDict]:
    """Convert old-style 'perspectives' configs into new-style 'trusted_key_servers'

    Returns an iterable of entries to add to trusted_key_servers.
    """

    # 'perspectives' looks like:
    #
    # {
    #     "servers": {
    #         "matrix.org": {
    #             "verify_keys": {
    #                 "ed25519:auto": {
    #                     "key": "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw"
    #                 }
    #             }
    #         }
    #     }
    # }
    #
    # 'trusted_keys' looks like:
    #
    # [
    #     {
    #         "server_name": "matrix.org",
    #         "verify_keys": {
    #             "ed25519:auto": "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw",
    #         }
    #     }
    # ]

    perspectives_servers = config.get("perspectives", {}).get("servers", {})

    for server_name, server_opts in perspectives_servers.items():
        trusted_key_server_entry = {"server_name": server_name}
        verify_keys = server_opts.get("verify_keys")
        if verify_keys is not None:
            trusted_key_server_entry["verify_keys"] = {
                key_id: key_data["key"] for key_id, key_data in verify_keys.items()
            }
        yield trusted_key_server_entry


TRUSTED_KEY_SERVERS_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "schema for the trusted_key_servers setting",
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "server_name": {"type": "string"},
            "verify_keys": {
                "type": "object",
                # each key must be a base64 string
                "additionalProperties": {"type": "string"},
            },
        },
        "required": ["server_name"],
    },
}


def _parse_key_servers(
    key_servers: List[Any], federation_verify_certificates: bool
) -> Iterator[TrustedKeyServer]:
    try:
        jsonschema.validate(key_servers, TRUSTED_KEY_SERVERS_SCHEMA)
    except jsonschema.ValidationError as e:
        raise ConfigError(
            "Unable to parse 'trusted_key_servers': {}".format(
                e.message  # noqa: B306, jsonschema.ValidationError.message is a valid attribute
            )
        )

    for server in key_servers:
        server_name = server["server_name"]
        result = TrustedKeyServer(server_name=server_name)

        verify_keys: Optional[Dict[str, str]] = server.get("verify_keys")
        if verify_keys is not None:
            result.verify_keys = {}
            for key_id, key_base64 in verify_keys.items():
                if not is_signing_algorithm_supported(key_id):
                    raise ConfigError(
                        "Unsupported signing algorithm on key %s for server %s in "
                        "trusted_key_servers" % (key_id, server_name)
                    )
                try:
                    key_bytes = decode_base64(key_base64)
                    verify_key = decode_verify_key_bytes(key_id, key_bytes)
                except Exception as e:
                    raise ConfigError(
                        "Unable to parse key %s for server %s in "
                        "trusted_key_servers: %s" % (key_id, server_name, e)
                    )

                result.verify_keys[key_id] = verify_key

        if not federation_verify_certificates and not server.get(
            "accept_keys_insecurely"
        ):
            _assert_keyserver_has_verify_keys(result)

        yield result


def _assert_keyserver_has_verify_keys(trusted_key_server: TrustedKeyServer) -> None:
    if not trusted_key_server.verify_keys:
        raise ConfigError(INSECURE_NOTARY_ERROR)

    # also check that they are not blindly checking the old matrix.org key
    if trusted_key_server.server_name == "matrix.org" and any(
        key_id == "ed25519:auto" for key_id in trusted_key_server.verify_keys
    ):
        raise ConfigError(RELYING_ON_MATRIX_KEY_ERROR)
