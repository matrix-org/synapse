# -*- coding: utf-8 -*-
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

import os

from OpenSSL import SSL

from synapse.config.tls import ConfigError, TlsConfig
from synapse.crypto.context_factory import ClientTLSOptionsFactory

from tests.unittest import TestCase


class TestConfig(TlsConfig):
    def has_tls_listener(self):
        return False


class TLSConfigTests(TestCase):
    def test_warn_self_signed(self):
        """
        Synapse will give a warning when it loads a self-signed certificate.
        """
        config_dir = self.mktemp()
        os.mkdir(config_dir)
        with open(os.path.join(config_dir, "cert.pem"), "w") as f:
            f.write(
                """-----BEGIN CERTIFICATE-----
MIID6DCCAtACAws9CjANBgkqhkiG9w0BAQUFADCBtzELMAkGA1UEBhMCVFIxDzAN
BgNVBAgMBsOHb3J1bTEUMBIGA1UEBwwLQmHFn21ha8OnxLExEjAQBgNVBAMMCWxv
Y2FsaG9zdDEcMBoGA1UECgwTVHdpc3RlZCBNYXRyaXggTGFiczEkMCIGA1UECwwb
QXV0b21hdGVkIFRlc3RpbmcgQXV0aG9yaXR5MSkwJwYJKoZIhvcNAQkBFhpzZWN1
cml0eUB0d2lzdGVkbWF0cml4LmNvbTAgFw0xNzA3MTIxNDAxNTNaGA8yMTE3MDYx
ODE0MDE1M1owgbcxCzAJBgNVBAYTAlRSMQ8wDQYDVQQIDAbDh29ydW0xFDASBgNV
BAcMC0JhxZ9tYWvDp8SxMRIwEAYDVQQDDAlsb2NhbGhvc3QxHDAaBgNVBAoME1R3
aXN0ZWQgTWF0cml4IExhYnMxJDAiBgNVBAsMG0F1dG9tYXRlZCBUZXN0aW5nIEF1
dGhvcml0eTEpMCcGCSqGSIb3DQEJARYac2VjdXJpdHlAdHdpc3RlZG1hdHJpeC5j
b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwT6kbqtMUI0sMkx4h
I+L780dA59KfksZCqJGmOsMD6hte9EguasfkZzvCF3dk3NhwCjFSOvKx6rCwiteo
WtYkVfo+rSuVNmt7bEsOUDtuTcaxTzIFB+yHOYwAaoz3zQkyVW0c4pzioiLCGCmf
FLdiDBQGGp74tb+7a0V6kC3vMLFoM3L6QWq5uYRB5+xLzlPJ734ltyvfZHL3Us6p
cUbK+3WTWvb4ER0W2RqArAj6Bc/ERQKIAPFEiZi9bIYTwvBH27OKHRz+KoY/G8zY
+l+WZoJqDhupRAQAuh7O7V/y6bSP+KNxJRie9QkZvw1PSaGSXtGJI3WWdO12/Ulg
epJpAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAJXEq5P9xwvP9aDkXIqzcD0L8sf8
ewlhlxTQdeqt2Nace0Yk18lIo2oj1t86Y8jNbpAnZJeI813Rr5M7FbHCXoRc/SZG
I8OtG1xGwcok53lyDuuUUDexnK4O5BkjKiVlNPg4HPim5Kuj2hRNFfNt/F2BVIlj
iZupikC5MT1LQaRwidkSNxCku1TfAyueiBwhLnFwTmIGNnhuDCutEVAD9kFmcJN2
SznugAcPk4doX2+rL+ila+ThqgPzIkwTUHtnmjI0TI6xsDUlXz5S3UyudrE2Qsfz
s4niecZKPBizL6aucT59CsunNmmb5Glq8rlAcU+1ZTZZzGYqVYhF6axB9Qg=
-----END CERTIFICATE-----"""
            )

        config = {
            "tls_certificate_path": os.path.join(config_dir, "cert.pem"),
            "tls_fingerprints": [],
        }

        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        t.read_certificate_from_disk(require_cert_and_key=False)

        warnings = self.flushWarnings()
        self.assertEqual(len(warnings), 1)
        self.assertEqual(
            warnings[0]["message"],
            (
                "Self-signed TLS certificates will not be accepted by "
                "Synapse 1.0. Please either provide a valid certificate, "
                "or use Synapse's ACME support to provision one."
            ),
        )

    def test_tls_client_minimum_default(self):
        """
        The default client TLS version is 1.0.
        """
        config = {}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

        self.assertEqual(t.federation_client_minimum_tls_version, "1")

    def test_tls_client_minimum_set(self):
        """
        The default client TLS version can be set to 1.0, 1.1, and 1.2.
        """
        config = {"federation_client_minimum_tls_version": 1}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.federation_client_minimum_tls_version, "1")

        config = {"federation_client_minimum_tls_version": 1.1}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.federation_client_minimum_tls_version, "1.1")

        config = {"federation_client_minimum_tls_version": 1.2}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.federation_client_minimum_tls_version, "1.2")

        # Also test a string version
        config = {"federation_client_minimum_tls_version": "1"}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.federation_client_minimum_tls_version, "1")

        config = {"federation_client_minimum_tls_version": "1.2"}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.federation_client_minimum_tls_version, "1.2")

    def test_tls_client_minimum_1_point_3_missing(self):
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

        config = {"federation_client_minimum_tls_version": 1.3}
        t = TestConfig()
        with self.assertRaises(ConfigError) as e:
            t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(
            e.exception.args[0],
            (
                "federation_client_minimum_tls_version cannot be 1.3, "
                "your OpenSSL does not support it"
            ),
        )

    def test_tls_client_minimum_1_point_3_exists(self):
        """
        If TLS 1.3 support exists and it's configured, it will be settable.
        """
        # thanks i hate it, still
        if not hasattr(SSL, "OP_NO_TLSv1_3"):
            SSL.OP_NO_TLSv1_3 = 0x00
            self.addCleanup(lambda: delattr(SSL, "OP_NO_TLSv1_3"))
            assert hasattr(SSL, "OP_NO_TLSv1_3")

        config = {"federation_client_minimum_tls_version": 1.3}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")
        self.assertEqual(t.federation_client_minimum_tls_version, "1.3")

    def test_tls_client_minimum_set_passed_through_1_2(self):
        """
        The configured TLS version is correctly configured by the ContextFactory.
        """
        config = {"federation_client_minimum_tls_version": 1.2}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

        cf = ClientTLSOptionsFactory(t)

        # The context has had NO_TLSv1_1 and NO_TLSv1_0 set, but not NO_TLSv1_2
        self.assertNotEqual(cf._verify_ssl._options & SSL.OP_NO_TLSv1, 0)
        self.assertNotEqual(cf._verify_ssl._options & SSL.OP_NO_TLSv1_1, 0)
        self.assertEqual(cf._verify_ssl._options & SSL.OP_NO_TLSv1_2, 0)

    def test_tls_client_minimum_set_passed_through_1_0(self):
        """
        The configured TLS version is correctly configured by the ContextFactory.
        """
        config = {"federation_client_minimum_tls_version": 1}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

        cf = ClientTLSOptionsFactory(t)

        # The context has not had any of the NO_TLS set.
        self.assertEqual(cf._verify_ssl._options & SSL.OP_NO_TLSv1, 0)
        self.assertEqual(cf._verify_ssl._options & SSL.OP_NO_TLSv1_1, 0)
        self.assertEqual(cf._verify_ssl._options & SSL.OP_NO_TLSv1_2, 0)
