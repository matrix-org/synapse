# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from OpenSSL import crypto
import subprocess
import os

GENERATE_DH_PARAMS = False


class TlsConfig(Config):
    def __init__(self, args):
        super(TlsConfig, self).__init__(args)
        self.tls_certificate = self.read_tls_certificate(
            args.tls_certificate_path
        )
        self.tls_private_key = self.read_tls_private_key(
            args.tls_private_key_path
        )
        self.tls_dh_params_path = self.check_file(
            args.tls_dh_params_path, "tls_dh_params"
        )

    @classmethod
    def add_arguments(cls, parser):
        super(TlsConfig, cls).add_arguments(parser)
        tls_group = parser.add_argument_group("tls")
        tls_group.add_argument("--tls-certificate-path",
                               help="PEM encoded X509 certificate for TLS")
        tls_group.add_argument("--tls-private-key-path",
                               help="PEM encoded private key for TLS")
        tls_group.add_argument("--tls-dh-params-path",
                               help="PEM dh parameters for ephemeral keys")

    def read_tls_certificate(self, cert_path):
        cert_pem = self.read_file(cert_path, "tls_certificate")
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    def read_tls_private_key(self, private_key_path):
        private_key_pem = self.read_file(private_key_path, "tls_private_key")
        return crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)

    @classmethod
    def generate_config(cls, args, config_dir_path):
        super(TlsConfig, cls).generate_config(args, config_dir_path)
        base_key_name = os.path.join(config_dir_path, args.server_name)

        if args.tls_certificate_path is None:
            args.tls_certificate_path = base_key_name + ".tls.crt"

        if args.tls_private_key_path is None:
            args.tls_private_key_path = base_key_name + ".tls.key"

        if args.tls_dh_params_path is None:
            args.tls_dh_params_path = base_key_name + ".tls.dh"

        if not os.path.exists(args.tls_private_key_path):
            with open(args.tls_private_key_path, "w") as private_key_file:
                tls_private_key = crypto.PKey()
                tls_private_key.generate_key(crypto.TYPE_RSA, 2048)
                private_key_pem = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, tls_private_key
                )
                private_key_file.write(private_key_pem)
        else:
            with open(args.tls_private_key_path) as private_key_file:
                private_key_pem = private_key_file.read()
                tls_private_key = crypto.load_privatekey(
                    crypto.FILETYPE_PEM, private_key_pem
                )

        if not os.path.exists(args.tls_certificate_path):
            with open(args.tls_certificate_path, "w") as certifcate_file:
                cert = crypto.X509()
                subject = cert.get_subject()
                subject.CN = args.server_name

                cert.set_serial_number(1000)
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
                cert.set_issuer(cert.get_subject())
                cert.set_pubkey(tls_private_key)

                cert.sign(tls_private_key, 'sha256')

                cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

                certifcate_file.write(cert_pem)

        if not os.path.exists(args.tls_dh_params_path):
            if GENERATE_DH_PARAMS:
                subprocess.check_call([
                    "openssl", "dhparam",
                    "-outform", "PEM",
                    "-out", args.tls_dh_params_path,
                    "2048"
                ])
            else:
                with open(args.tls_dh_params_path, "w") as dh_params_file:
                    dh_params_file.write(
                        "2048-bit DH parameters taken from rfc3526\n"
                        "-----BEGIN DH PARAMETERS-----\n"
                        "MIIBCAKCAQEA///////////JD9qiIWjC"
                        "NMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\n"
                        "IlFKCHmONATd75UZs806QxswKwpt8l8U"
                        "N0/hNW1tUcJF5IW1dmJefsb0TELppjft\n"
                        "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf"
                        "5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\n"
                        "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVS"
                        "u57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\n"
                        "fDKQXkYuNs474553LBgOhgObJ4Oi7Aei"
                        "j7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\n"
                        "5RXSJhiY+gUQFXKOWoqsqmj/////////"
                        "/wIBAg==\n"
                        "-----END DH PARAMETERS-----\n"
                    )
