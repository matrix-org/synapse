# Copyright 2019 New Vector Ltd
# Copyright 2019 Matrix.org Foundation C.I.C.
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

from typing import cast

import idna

from OpenSSL import SSL

from synapse.config._base import Config, RootConfig
from synapse.config.homeserver import HomeServerConfig
from synapse.config.tls import ConfigError, TlsConfig
from synapse.crypto.context_factory import (
    FederationPolicyForHTTPS,
    SSLClientConnectionCreator,
)
from synapse.types import JsonDict

from tests.unittest import TestCase


class FakeServer(Config):
    section = "server"

    def has_tls_listener(self) -> bool:
        return False


class TestConfig(RootConfig):
    config_classes = [FakeServer, TlsConfig]


class TLSConfigTests(TestCase):
    def test_tls_client_minimum_default(self) -> None:
        """
        The default client TLS version is 1.0.
        """
        config: JsonDict = {}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")

        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1")

    def test_tls_client_minimum_set(self) -> None:
        """
        The default client TLS version can be set to 1.0, 1.1, and 1.2.
        """
        config: JsonDict = {"federation_client_minimum_tls_version": 1}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1")

        config = {"federation_client_minimum_tls_version": 1.1}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1.1")

        config = {"federation_client_minimum_tls_version": 1.2}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1.2")

        # Also test a string version
        config = {"federation_client_minimum_tls_version": "1"}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1")

        config = {"federation_client_minimum_tls_version": "1.2"}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1.2")

    def test_tls_client_minimum_1_point_3_missing(self) -> None:
        """
        If TLS 1.3 support is missing and it's configured, it will raise a
        ConfigError.
        """
        # thanks i hate it
        if hasattr(SSL, "OP_NO_TLSv1_3"):
            OP_NO_TLSv1_3 = SSL.OP_NO_TLSv1_3
            delattr(SSL, "OP_NO_TLSv1_3")
            self.addCleanup(setattr, SSL, "SSL.OP_NO_TLSv1_3", OP_NO_TLSv1_3)
            assert not hasattr(SSL, "OP_NO_TLSv1_3")

        config: JsonDict = {"federation_client_minimum_tls_version": 1.3}
        t = TestConfig()
        with self.assertRaises(ConfigError) as e:
            t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(
            e.exception.args[0],
            (
                "federation_client_minimum_tls_version cannot be 1.3, "
                "your OpenSSL does not support it"
            ),
        )

    def test_tls_client_minimum_1_point_3_exists(self) -> None:
        """
        If TLS 1.3 support exists and it's configured, it will be settable.
        """
        # thanks i hate it, still
        if not hasattr(SSL, "OP_NO_TLSv1_3"):
            SSL.OP_NO_TLSv1_3 = 0x00
            self.addCleanup(lambda: delattr(SSL, "OP_NO_TLSv1_3"))
            assert hasattr(SSL, "OP_NO_TLSv1_3")

        config: JsonDict = {"federation_client_minimum_tls_version": 1.3}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.tls.federation_client_minimum_tls_version, "1.3")

    def test_tls_client_minimum_set_passed_through_1_2(self) -> None:
        """
        The configured TLS version is correctly configured by the ContextFactory.
        """
        config: JsonDict = {"federation_client_minimum_tls_version": 1.2}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")

        cf = FederationPolicyForHTTPS(cast(HomeServerConfig, t))
        options = _get_ssl_context_options(cf._verify_ssl_context)

        # The context has had NO_TLSv1_1 and NO_TLSv1_0 set, but not NO_TLSv1_2
        self.assertNotEqual(options & SSL.OP_NO_TLSv1, 0)
        self.assertNotEqual(options & SSL.OP_NO_TLSv1_1, 0)
        self.assertEqual(options & SSL.OP_NO_TLSv1_2, 0)

    def test_tls_client_minimum_set_passed_through_1_0(self) -> None:
        """
        The configured TLS version is correctly configured by the ContextFactory.
        """
        config: JsonDict = {"federation_client_minimum_tls_version": 1}
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")

        cf = FederationPolicyForHTTPS(cast(HomeServerConfig, t))
        options = _get_ssl_context_options(cf._verify_ssl_context)

        # The context has not had any of the NO_TLS set.
        self.assertEqual(options & SSL.OP_NO_TLSv1, 0)
        self.assertEqual(options & SSL.OP_NO_TLSv1_1, 0)
        self.assertEqual(options & SSL.OP_NO_TLSv1_2, 0)

    def test_whitelist_idna_failure(self) -> None:
        """
        The federation certificate whitelist will not allow IDNA domain names.
        """
        config: JsonDict = {
            "federation_certificate_verification_whitelist": [
                "example.com",
                "*.ドメイン.テスト",
            ]
        }
        t = TestConfig()
        e = self.assertRaises(
            ConfigError, t.tls.read_config, config, config_dir_path="", data_dir_path=""
        )
        self.assertIn("IDNA domain names", str(e))

    def test_whitelist_idna_result(self) -> None:
        """
        The federation certificate whitelist will match on IDNA encoded names.
        """
        config: JsonDict = {
            "federation_certificate_verification_whitelist": [
                "example.com",
                "*.xn--eckwd4c7c.xn--zckzah",
            ]
        }
        t = TestConfig()
        t.tls.read_config(config, config_dir_path="", data_dir_path="")

        cf = FederationPolicyForHTTPS(cast(HomeServerConfig, t))

        # Not in the whitelist
        opts = cf.get_options(b"notexample.com")
        assert isinstance(opts, SSLClientConnectionCreator)
        self.assertTrue(opts._verifier._verify_certs)

        # Caught by the wildcard
        opts = cf.get_options(idna.encode("テスト.ドメイン.テスト"))
        assert isinstance(opts, SSLClientConnectionCreator)
        self.assertFalse(opts._verifier._verify_certs)


def _get_ssl_context_options(ssl_context: SSL.Context) -> int:
    """get the options bits from an openssl context object"""
    # the OpenSSL.SSL.Context wrapper doesn't expose get_options, so we have to
    # use the low-level interface
    return SSL._lib.SSL_CTX_get_options(ssl_context._context)  # type: ignore[attr-defined]
