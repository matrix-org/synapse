# Copyright 2014-2016 OpenMarket Ltd
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

import logging
from typing import Any, List, Optional, Pattern

from matrix_common.regex import glob_to_regex

from OpenSSL import SSL, crypto
from twisted.internet._sslverify import Certificate, trustRootFromCertificates

from synapse.config._base import Config, ConfigError
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class TlsConfig(Config):
    section = "tls"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:

        self.tls_certificate_file = self.abspath(config.get("tls_certificate_path"))
        self.tls_private_key_file = self.abspath(config.get("tls_private_key_path"))

        if self.root.server.has_tls_listener():
            if not self.tls_certificate_file:
                raise ConfigError(
                    "tls_certificate_path must be specified if TLS-enabled listeners are "
                    "configured."
                )
            if not self.tls_private_key_file:
                raise ConfigError(
                    "tls_private_key_path must be specified if TLS-enabled listeners are "
                    "configured."
                )

        # Whether to verify certificates on outbound federation traffic
        self.federation_verify_certificates = config.get(
            "federation_verify_certificates", True
        )

        # Minimum TLS version to use for outbound federation traffic
        self.federation_client_minimum_tls_version = str(
            config.get("federation_client_minimum_tls_version", 1)
        )

        if self.federation_client_minimum_tls_version not in ["1", "1.1", "1.2", "1.3"]:
            raise ConfigError(
                "federation_client_minimum_tls_version must be one of: 1, 1.1, 1.2, 1.3"
            )

        # Prevent people shooting themselves in the foot here by setting it to
        # the biggest number blindly
        if self.federation_client_minimum_tls_version == "1.3":
            if getattr(SSL, "OP_NO_TLSv1_3", None) is None:
                raise ConfigError(
                    "federation_client_minimum_tls_version cannot be 1.3, "
                    "your OpenSSL does not support it"
                )

        # Whitelist of domains to not verify certificates for
        fed_whitelist_entries = config.get(
            "federation_certificate_verification_whitelist", []
        )
        if fed_whitelist_entries is None:
            fed_whitelist_entries = []

        # Support globs (*) in whitelist values
        self.federation_certificate_verification_whitelist: List[Pattern] = []
        for entry in fed_whitelist_entries:
            try:
                entry_regex = glob_to_regex(entry.encode("ascii").decode("ascii"))
            except UnicodeEncodeError:
                raise ConfigError(
                    "IDNA domain names are not allowed in the "
                    "federation_certificate_verification_whitelist: %s" % (entry,)
                )

            # Convert globs to regex
            self.federation_certificate_verification_whitelist.append(entry_regex)

        # List of custom certificate authorities for federation traffic validation
        custom_ca_list = config.get("federation_custom_ca_list", None)

        # Read in and parse custom CA certificates
        self.federation_ca_trust_root = None
        if custom_ca_list is not None:
            if len(custom_ca_list) == 0:
                # A trustroot cannot be generated without any CA certificates.
                # Raise an error if this option has been specified without any
                # corresponding certificates.
                raise ConfigError(
                    "federation_custom_ca_list specified without "
                    "any certificate files"
                )

            certs = []
            for ca_file in custom_ca_list:
                logger.debug("Reading custom CA certificate file: %s", ca_file)
                content = self.read_file(ca_file, "federation_custom_ca_list")

                # Parse the CA certificates
                try:
                    cert_base = Certificate.loadPEM(content)
                    certs.append(cert_base)
                except Exception as e:
                    raise ConfigError(
                        "Error parsing custom CA certificate file %s: %s" % (ca_file, e)
                    )

            self.federation_ca_trust_root = trustRootFromCertificates(certs)

        # This config option applies to non-federation HTTP clients
        # (e.g. for talking to recaptcha, identity servers, and such)
        # It should never be used in production, and is intended for
        # use only when running tests.
        self.use_insecure_ssl_client_just_for_testing_do_not_use = config.get(
            "use_insecure_ssl_client_just_for_testing_do_not_use"
        )

        self.tls_certificate: Optional[crypto.X509] = None
        self.tls_private_key: Optional[crypto.PKey] = None

    def read_certificate_from_disk(self) -> None:
        """
        Read the certificates and private key from disk.
        """
        self.tls_private_key = self.read_tls_private_key()
        self.tls_certificate = self.read_tls_certificate()

    def generate_config_section(
        self,
        tls_certificate_path: Optional[str],
        tls_private_key_path: Optional[str],
        **kwargs: Any,
    ) -> str:
        """If the TLS paths are not specified the default will be certs in the
        config directory"""

        if bool(tls_certificate_path) != bool(tls_private_key_path):
            raise ConfigError(
                "Please specify both a cert path and a key path or neither."
            )

        if tls_certificate_path and tls_private_key_path:
            return f"""\
                tls_certificate_path: {tls_certificate_path}
                tls_private_key_path: {tls_private_key_path}
                """
        else:
            return ""

    def read_tls_certificate(self) -> crypto.X509:
        """Reads the TLS certificate from the configured file, and returns it

        Returns:
            The certificate
        """
        cert_path = self.tls_certificate_file
        logger.info("Loading TLS certificate from %s", cert_path)
        cert_pem = self.read_file(cert_path, "tls_certificate_path")
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())

        return cert

    def read_tls_private_key(self) -> crypto.PKey:
        """Reads the TLS private key from the configured file, and returns it

        Returns:
            The private key
        """
        private_key_path = self.tls_private_key_file
        logger.info("Loading TLS key from %s", private_key_path)
        private_key_pem = self.read_file(private_key_path, "tls_private_key_path")
        return crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
