#!/usr/bin/env python
#
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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

from __future__ import print_function

import argparse
import nacl.signing
import json
import base64
import requests
import sys
import srvlookup
import yaml

def encode_base64(input_bytes):
    """Encode bytes as a base64 string without any padding."""

    input_len = len(input_bytes)
    output_len = 4 * ((input_len + 2) // 3) + (input_len + 2) % 3 - 2
    output_bytes = base64.b64encode(input_bytes)
    output_string = output_bytes[:output_len].decode("ascii")
    return output_string


def decode_base64(input_string):
    """Decode a base64 string to bytes inferring padding from the length of the
    string."""

    input_bytes = input_string.encode("ascii")
    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))
    output_len = 3 * ((input_len + 2) // 4) + (input_len + 2) % 4 - 2
    output_bytes = base64.b64decode(input_bytes + padding)
    return output_bytes[:output_len]


def encode_canonical_json(value):
    return json.dumps(
         value,
         # Encode code-points outside of ASCII as UTF-8 rather than \u escapes
         ensure_ascii=False,
         # Remove unecessary white space.
         separators=(',',':'),
         # Sort the keys of dictionaries.
         sort_keys=True,
         # Encode the resulting unicode as UTF-8 bytes.
     ).encode("UTF-8")


def sign_json(json_object, signing_key, signing_name):
    signatures = json_object.pop("signatures", {})
    unsigned = json_object.pop("unsigned", None)

    signed = signing_key.sign(encode_canonical_json(json_object))
    signature_base64 = encode_base64(signed.signature)

    key_id = "%s:%s" % (signing_key.alg, signing_key.version)
    signatures.setdefault(signing_name, {})[key_id] = signature_base64

    json_object["signatures"] = signatures
    if unsigned is not None:
        json_object["unsigned"] = unsigned

    return json_object


NACL_ED25519 = "ed25519"

def decode_signing_key_base64(algorithm, version, key_base64):
    """Decode a base64 encoded signing key
    Args:
        algorithm (str): The algorithm the key is for (currently "ed25519").
        version (str): Identifies this key out of the keys for this entity.
        key_base64 (str): Base64 encoded bytes of the key.
    Returns:
        A SigningKey object.
    """
    if algorithm == NACL_ED25519:
        key_bytes = decode_base64(key_base64)
        key = nacl.signing.SigningKey(key_bytes)
        key.version = version
        key.alg = NACL_ED25519
        return key
    else:
        raise ValueError("Unsupported algorithm %s" % (algorithm,))


def read_signing_keys(stream):
    """Reads a list of keys from a stream
    Args:
        stream : A stream to iterate for keys.
    Returns:
        list of SigningKey objects.
    """
    keys = []
    for line in stream:
        algorithm, version, key_base64 = line.split()
        keys.append(decode_signing_key_base64(algorithm, version, key_base64))
    return keys


def lookup(destination, path):
    if ":" in destination:
        return "https://%s%s" % (destination, path)
    else:
        try:
            srv = srvlookup.lookup("matrix", "tcp", destination)[0]
            return "https://%s:%d%s" % (srv.host, srv.port, path)
        except:
            return "https://%s:%d%s" % (destination, 8448, path)

def get_json(origin_name, origin_key, destination, path):
    request_json = {
        "method": "GET",
        "uri": path,
        "origin": origin_name,
        "destination": destination,
    }

    signed_json = sign_json(request_json, origin_key, origin_name)

    authorization_headers = []

    for key, sig in signed_json["signatures"][origin_name].items():
        header = "X-Matrix origin=%s,key=\"%s\",sig=\"%s\"" % (
            origin_name, key, sig,
        )
        authorization_headers.append(bytes(header))
        print ("Authorization: %s" % header, file=sys.stderr)

    dest = lookup(destination, path)
    print ("Requesting %s" % dest, file=sys.stderr)

    result = requests.get(
        dest,
        headers={"Authorization": authorization_headers[0]},
        verify=False,
    )
    sys.stderr.write("Status Code: %d\n" % (result.status_code,))
    return result.json()


def main():
    parser = argparse.ArgumentParser(
        description=
            "Signs and sends a federation request to a matrix homeserver",
    )

    parser.add_argument(
        "-N", "--server-name",
        help="Name to give as the local homeserver. If unspecified, will be "
             "read from the config file.",
    )

    parser.add_argument(
        "-k", "--signing-key-path",
        help="Path to the file containing the private ed25519 key to sign the "
             "request with.",
    )

    parser.add_argument(
        "-c", "--config",
        default="homeserver.yaml",
        help="Path to server config file. Ignored if --server-name and "
             "--signing-key-path are both given.",
    )

    parser.add_argument(
        "-d", "--destination",
        default="matrix.org",
        help="name of the remote homeserver. We will do SRV lookups and "
             "connect appropriately.",
    )

    parser.add_argument(
        "path",
        help="request path. We will add '/_matrix/federation/v1/' to this."
    )

    args = parser.parse_args()

    if not args.server_name or not args.signing_key_path:
        read_args_from_config(args)

    with open(args.signing_key_path) as f:
        key = read_signing_keys(f)[0]

    result = get_json(
        args.server_name, key, args.destination, "/_matrix/federation/v1/" + args.path
    )

    json.dump(result, sys.stdout)
    print ("")


def read_args_from_config(args):
    with open(args.config, 'r') as fh:
        config = yaml.safe_load(fh)
        if not args.server_name:
            args.server_name = config['server_name']
        if not args.signing_key_path:
            args.signing_key_path = config['signing_key_path']


if __name__ == "__main__":
    main()
