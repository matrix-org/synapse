# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

import ConfigParser as configparser
import argparse
import socket
import sys
import os
from OpenSSL import crypto
import nacl.signing
from syutil.base64util import encode_base64
import subprocess


def load_config(description, argv):
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("-c", "--config-path", metavar="CONFIG_FILE",
                               help="Specify config file")
    config_args, remaining_args = config_parser.parse_known_args(argv)
    if config_args.config_path:
        config = configparser.SafeConfigParser()
        config.read([config_args.config_path])
        defaults = dict(config.items("KeyServer"))
    else:
        defaults = {}
    parser = argparse.ArgumentParser(
        parents=[config_parser],
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.set_defaults(**defaults)
    parser.add_argument("--server-name", default=socket.getfqdn(),
                        help="The name of the server")
    parser.add_argument("--signing-key-path",
                        help="The signing key to sign responses with")
    parser.add_argument("--tls-certificate-path",
                        help="PEM encoded X509 certificate for TLS")
    parser.add_argument("--tls-private-key-path",
                        help="PEM encoded private key for TLS")
    parser.add_argument("--tls-dh-params-path",
                        help="PEM encoded dh parameters for ephemeral keys")
    parser.add_argument("--bind-port", type=int,
                        help="TCP port to listen on")
    parser.add_argument("--bind-host", default="",
                        help="Local interface to listen on")

    args = parser.parse_args(remaining_args)

    server_config = vars(args)
    del server_config["config_path"]
    return server_config


def generate_config(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config-path", help="Specify config file",
                        metavar="CONFIG_FILE", required=True)
    parser.add_argument("--server-name", default=socket.getfqdn(),
                        help="The name of the server")
    parser.add_argument("--signing-key-path",
                        help="The signing key to sign responses with")
    parser.add_argument("--tls-certificate-path",
                        help="PEM encoded X509 certificate for TLS")
    parser.add_argument("--tls-private-key-path",
                        help="PEM encoded private key for TLS")
    parser.add_argument("--tls-dh-params-path",
                        help="PEM encoded dh parameters for ephemeral keys")
    parser.add_argument("--bind-port", type=int, required=True,
                        help="TCP port to listen on")
    parser.add_argument("--bind-host", default="",
                        help="Local interface to listen on")

    args = parser.parse_args(argv)

    dir_name = os.path.dirname(args.config_path)
    base_key_name = os.path.join(dir_name, args.server_name)

    if args.signing_key_path is None:
        args.signing_key_path = base_key_name + ".signing.key"

    if args.tls_certificate_path is None:
        args.tls_certificate_path = base_key_name + ".tls.crt"

    if args.tls_private_key_path is None:
        args.tls_private_key_path = base_key_name + ".tls.key"

    if args.tls_dh_params_path is None:
        args.tls_dh_params_path = base_key_name + ".tls.dh"

    if not os.path.exists(args.signing_key_path):
        with open(args.signing_key_path, "w") as signing_key_file:
            key = nacl.signing.SigningKey.generate()
            signing_key_file.write(encode_base64(key.encode()))

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
        subprocess.check_call([
            "openssl", "dhparam",
            "-outform", "PEM",
            "-out", args.tls_dh_params_path,
            "2048"
        ])

    config = configparser.SafeConfigParser()
    config.add_section("KeyServer")
    for key, value in vars(args).items():
        if key != "config_path":
            config.set("KeyServer", key, str(value))

    with open(args.config_path, "w") as config_file:
        config.write(config_file)


if __name__ == "__main__":
    generate_config(sys.argv[1:])
