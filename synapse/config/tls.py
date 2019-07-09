# -*- coding: utf-8 -*-
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
import os
import warnings
from datetime import datetime
from hashlib import sha256

import six

from unpaddedbase64 import encode_base64

from OpenSSL import SSL, crypto
from twisted.internet._sslverify import Certificate, trustRootFromCertificates

from synapse.config._base import Config, ConfigError
from synapse.util import glob_to_regex

logger = logging.getLogger(__name__)


class TlsConfig(Config):
    def read_config(self, config, config_dir_path, **kwargs):

        acme_config = config.get("acme", None)
        if acme_config is None:
            acme_config = {}

        self.acme_enabled = acme_config.get("enabled", False)

        # hyperlink complains on py2 if this is not a Unicode
        self.acme_url = six.text_type(
            acme_config.get("url", "https://acme-v01.api.letsencrypt.org/directory")
        )
        self.acme_port = acme_config.get("port", 80)
        self.acme_bind_addresses = acme_config.get("bind_addresses", ["::", "0.0.0.0"])
        self.acme_reprovision_threshold = acme_config.get("reprovision_threshold", 30)
        self.acme_domain = acme_config.get("domain", config.get("server_name"))

        self.acme_account_key_file = self.abspath(
            acme_config.get("account_key_file", config_dir_path + "/client.key")
        )

        self.tls_certificate_file = self.abspath(config.get("tls_certificate_path"))
        self.tls_private_key_file = self.abspath(config.get("tls_private_key_path"))

        if self.has_tls_listener():
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

        self._original_tls_fingerprints = config.get("tls_fingerprints", [])

        if self._original_tls_fingerprints is None:
            self._original_tls_fingerprints = []

        self.tls_fingerprints = list(self._original_tls_fingerprints)

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
                    (
                        "federation_client_minimum_tls_version cannot be 1.3, "
                        "your OpenSSL does not support it"
                    )
                )

        # Whitelist of domains to not verify certificates for
        fed_whitelist_entries = config.get(
            "federation_certificate_verification_whitelist", []
        )

        # Support globs (*) in whitelist values
        self.federation_certificate_verification_whitelist = []
        for entry in fed_whitelist_entries:
            # Convert globs to regex
            entry_regex = glob_to_regex(entry)
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

        self.tls_certificate = None
        self.tls_private_key = None

    def is_disk_cert_valid(self, allow_self_signed=True):
        """
        Is the certificate we have on disk valid, and if so, for how long?

        Args:
            allow_self_signed (bool): Should we allow the certificate we
                read to be self signed?

        Returns:
            int: Days remaining of certificate validity.
            None: No certificate exists.
        """
        if not os.path.exists(self.tls_certificate_file):
            return None

        try:
            with open(self.tls_certificate_file, "rb") as f:
                cert_pem = f.read()
        except Exception as e:
            raise ConfigError(
                "Failed to read existing certificate file %s: %s"
                % (self.tls_certificate_file, e)
            )

        try:
            tls_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        except Exception as e:
            raise ConfigError(
                "Failed to parse existing certificate file %s: %s"
                % (self.tls_certificate_file, e)
            )

        if not allow_self_signed:
            if tls_certificate.get_subject() == tls_certificate.get_issuer():
                raise ValueError(
                    "TLS Certificate is self signed, and this is not permitted"
                )

        # YYYYMMDDhhmmssZ -- in UTC
        expires_on = datetime.strptime(
            tls_certificate.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ"
        )
        now = datetime.utcnow()
        days_remaining = (expires_on - now).days
        return days_remaining

    def read_certificate_from_disk(self, require_cert_and_key):
        """
        Read the certificates and private key from disk.

        Args:
            require_cert_and_key (bool): set to True to throw an error if the certificate
                and key file are not given
        """
        if require_cert_and_key:
            self.tls_private_key = self.read_tls_private_key()
            self.tls_certificate = self.read_tls_certificate()
        elif self.tls_certificate_file:
            # we only need the certificate for the tls_fingerprints. Reload it if we
            # can, but it's not a fatal error if we can't.
            try:
                self.tls_certificate = self.read_tls_certificate()
            except Exception as e:
                logger.info(
                    "Unable to read TLS certificate (%s). Ignoring as no "
                    "tls listeners enabled.",
                    e,
                )

        self.tls_fingerprints = list(self._original_tls_fingerprints)

        if self.tls_certificate:
            # Check that our own certificate is included in the list of fingerprints
            # and include it if it is not.
            x509_certificate_bytes = crypto.dump_certificate(
                crypto.FILETYPE_ASN1, self.tls_certificate
            )
            sha256_fingerprint = encode_base64(sha256(x509_certificate_bytes).digest())
            sha256_fingerprints = set(f["sha256"] for f in self.tls_fingerprints)
            if sha256_fingerprint not in sha256_fingerprints:
                self.tls_fingerprints.append({"sha256": sha256_fingerprint})

    def generate_config_section(
        self, config_dir_path, server_name, data_dir_path, **kwargs
    ):
        base_key_name = os.path.join(config_dir_path, server_name)

        tls_certificate_path = base_key_name + ".tls.crt"
        tls_private_key_path = base_key_name + ".tls.key"
        default_acme_account_file = os.path.join(data_dir_path, "acme_account.key")

        # this is to avoid the max line length. Sorrynotsorry
        proxypassline = (
            "ProxyPass /.well-known/acme-challenge "
            "http://localhost:8009/.well-known/acme-challenge"
        )

        return (
            """\
        ## TLS ##

        # PEM-encoded X509 certificate for TLS.
        # This certificate, as of Synapse 1.0, will need to be a valid and verifiable
        # certificate, signed by a recognised Certificate Authority.
        #
        # See 'ACME support' below to enable auto-provisioning this certificate via
        # Let's Encrypt.
        #
        # If supplying your own, be sure to use a `.pem` file that includes the
        # full certificate chain including any intermediate certificates (for
        # instance, if using certbot, use `fullchain.pem` as your certificate,
        # not `cert.pem`).
        #
        #tls_certificate_path: "%(tls_certificate_path)s"

        # PEM-encoded private key for TLS
        #
        #tls_private_key_path: "%(tls_private_key_path)s"

        # Whether to verify TLS server certificates for outbound federation requests.
        #
        # Defaults to `true`. To disable certificate verification, uncomment the
        # following line.
        #
        #federation_verify_certificates: false

        # The minimum TLS version that will be used for outbound federation requests.
        #
        # Defaults to `1`. Configurable to `1`, `1.1`, `1.2`, or `1.3`. Note
        # that setting this value higher than `1.2` will prevent federation to most
        # of the public Matrix network: only configure it to `1.3` if you have an
        # entirely private federation setup and you can ensure TLS 1.3 support.
        #
        #federation_client_minimum_tls_version: 1.2

        # Skip federation certificate verification on the following whitelist
        # of domains.
        #
        # This setting should only be used in very specific cases, such as
        # federation over Tor hidden services and similar. For private networks
        # of homeservers, you likely want to use a private CA instead.
        #
        # Only effective if federation_verify_certicates is `true`.
        #
        #federation_certificate_verification_whitelist:
        #  - lon.example.com
        #  - *.domain.com
        #  - *.onion

        # List of custom certificate authorities for federation traffic.
        #
        # This setting should only normally be used within a private network of
        # homeservers.
        #
        # Note that this list will replace those that are provided by your
        # operating environment. Certificates must be in PEM format.
        #
        #federation_custom_ca_list:
        #  - myCA1.pem
        #  - myCA2.pem
        #  - myCA3.pem

        # ACME support: This will configure Synapse to request a valid TLS certificate
        # for your configured `server_name` via Let's Encrypt.
        #
        # Note that provisioning a certificate in this way requires port 80 to be
        # routed to Synapse so that it can complete the http-01 ACME challenge.
        # By default, if you enable ACME support, Synapse will attempt to listen on
        # port 80 for incoming http-01 challenges - however, this will likely fail
        # with 'Permission denied' or a similar error.
        #
        # There are a couple of potential solutions to this:
        #
        #  * If you already have an Apache, Nginx, or similar listening on port 80,
        #    you can configure Synapse to use an alternate port, and have your web
        #    server forward the requests. For example, assuming you set 'port: 8009'
        #    below, on Apache, you would write:
        #
        #    %(proxypassline)s
        #
        #  * Alternatively, you can use something like `authbind` to give Synapse
        #    permission to listen on port 80.
        #
        acme:
            # ACME support is disabled by default. Uncomment the following line
            # (and tls_certificate_path and tls_private_key_path above) to enable it.
            #
            #enabled: true

            # Endpoint to use to request certificates. If you only want to test,
            # use Let's Encrypt's staging url:
            #     https://acme-staging.api.letsencrypt.org/directory
            #
            #url: https://acme-v01.api.letsencrypt.org/directory

            # Port number to listen on for the HTTP-01 challenge. Change this if
            # you are forwarding connections through Apache/Nginx/etc.
            #
            #port: 80

            # Local addresses to listen on for incoming connections.
            # Again, you may want to change this if you are forwarding connections
            # through Apache/Nginx/etc.
            #
            #bind_addresses: ['::', '0.0.0.0']

            # How many days remaining on a certificate before it is renewed.
            #
            #reprovision_threshold: 30

            # The domain that the certificate should be for. Normally this
            # should be the same as your Matrix domain (i.e., 'server_name'), but,
            # by putting a file at 'https://<server_name>/.well-known/matrix/server',
            # you can delegate incoming traffic to another server. If you do that,
            # you should give the target of the delegation here.
            #
            # For example: if your 'server_name' is 'example.com', but
            # 'https://example.com/.well-known/matrix/server' delegates to
            # 'matrix.example.com', you should put 'matrix.example.com' here.
            #
            # If not set, defaults to your 'server_name'.
            #
            #domain: matrix.example.com

            # file to use for the account key. This will be generated if it doesn't
            # exist.
            #
            # If unspecified, we will use CONFDIR/client.key.
            #
            account_key_file: %(default_acme_account_file)s

        # List of allowed TLS fingerprints for this server to publish along
        # with the signing keys for this server. Other matrix servers that
        # make HTTPS requests to this server will check that the TLS
        # certificates returned by this server match one of the fingerprints.
        #
        # Synapse automatically adds the fingerprint of its own certificate
        # to the list. So if federation traffic is handled directly by synapse
        # then no modification to the list is required.
        #
        # If synapse is run behind a load balancer that handles the TLS then it
        # will be necessary to add the fingerprints of the certificates used by
        # the loadbalancers to this list if they are different to the one
        # synapse is using.
        #
        # Homeservers are permitted to cache the list of TLS fingerprints
        # returned in the key responses up to the "valid_until_ts" returned in
        # key. It may be necessary to publish the fingerprints of a new
        # certificate and wait until the "valid_until_ts" of the previous key
        # responses have passed before deploying it.
        #
        # You can calculate a fingerprint from a given TLS listener via:
        # openssl s_client -connect $host:$port < /dev/null 2> /dev/null |
        #   openssl x509 -outform DER | openssl sha256 -binary | base64 | tr -d '='
        # or by checking matrix.org/federationtester/api/report?server_name=$host
        #
        #tls_fingerprints: [{"sha256": "<base64_encoded_sha256_fingerprint>"}]

        """
            % locals()
        )

    def read_tls_certificate(self):
        """Reads the TLS certificate from the configured file, and returns it

        Also checks if it is self-signed, and warns if so

        Returns:
            OpenSSL.crypto.X509: the certificate
        """
        cert_path = self.tls_certificate_file
        logger.info("Loading TLS certificate from %s", cert_path)
        cert_pem = self.read_file(cert_path, "tls_certificate_path")
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # Check if it is self-signed, and issue a warning if so.
        if cert.get_issuer() == cert.get_subject():
            warnings.warn(
                (
                    "Self-signed TLS certificates will not be accepted by Synapse 1.0. "
                    "Please either provide a valid certificate, or use Synapse's ACME "
                    "support to provision one."
                )
            )

        return cert

    def read_tls_private_key(self):
        """Reads the TLS private key from the configured file, and returns it

        Returns:
            OpenSSL.crypto.PKey: the private key
        """
        private_key_path = self.tls_private_key_file
        logger.info("Loading TLS key from %s", private_key_path)
        private_key_pem = self.read_file(private_key_path, "tls_private_key_path")
        return crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
