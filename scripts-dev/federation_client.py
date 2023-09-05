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


"""
Script for signing and sending federation requests.

Some tips on doing the join dance with this:

    room_id=...
    user_id=...

    # make_join
    federation_client.py "/_matrix/federation/v1/make_join/$room_id/$user_id?ver=5" > make_join.json

    # sign
    jq -M .event make_join.json | sign_json --sign-event-room-version=$(jq -r .room_version make_join.json) -o signed-join.json

    # send_join
    federation_client.py -X PUT "/_matrix/federation/v2/send_join/$room_id/x" --body $(<signed-join.json) > send_join.json
"""

import argparse
import base64
import json
import sys
from typing import Any, Dict, Optional, Tuple
from urllib import parse as urlparse

import requests
import signedjson.key
import signedjson.types
import srvlookup
import yaml
from requests import PreparedRequest, Response
from requests.adapters import HTTPAdapter
from urllib3 import HTTPConnectionPool

# uncomment the following to enable debug logging of http requests
# from http.client import HTTPConnection
# HTTPConnection.debuglevel = 1


def encode_base64(input_bytes: bytes) -> str:
    """Encode bytes as a base64 string without any padding."""

    input_len = len(input_bytes)
    output_len = 4 * ((input_len + 2) // 3) + (input_len + 2) % 3 - 2
    output_bytes = base64.b64encode(input_bytes)
    output_string = output_bytes[:output_len].decode("ascii")
    return output_string


def encode_canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        # Encode code-points outside of ASCII as UTF-8 rather than \u escapes
        ensure_ascii=False,
        # Remove unecessary white space.
        separators=(",", ":"),
        # Sort the keys of dictionaries.
        sort_keys=True,
        # Encode the resulting unicode as UTF-8 bytes.
    ).encode("UTF-8")


def sign_json(
    json_object: Any, signing_key: signedjson.types.SigningKey, signing_name: str
) -> Any:
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


def request(
    method: Optional[str],
    origin_name: str,
    origin_key: signedjson.types.SigningKey,
    destination: str,
    path: str,
    content: Optional[str],
    verify_tls: bool,
) -> requests.Response:
    if method is None:
        if content is None:
            method = "GET"
        else:
            method = "POST"

    json_to_sign = {
        "method": method,
        "uri": path,
        "origin": origin_name,
        "destination": destination,
    }

    if content is not None:
        json_to_sign["content"] = json.loads(content)

    signed_json = sign_json(json_to_sign, origin_key, origin_name)

    authorization_headers = []

    for key, sig in signed_json["signatures"][origin_name].items():
        header = 'X-Matrix origin=%s,key="%s",sig="%s",destination="%s"' % (
            origin_name,
            key,
            sig,
            destination,
        )
        authorization_headers.append(header)
        print("Authorization: %s" % header, file=sys.stderr)

    dest = "matrix-federation://%s%s" % (destination, path)
    print("Requesting %s" % dest, file=sys.stderr)

    s = requests.Session()
    s.mount("matrix-federation://", MatrixConnectionAdapter())

    headers: Dict[str, str] = {
        "Authorization": authorization_headers[0],
    }

    if method == "POST":
        headers["Content-Type"] = "application/json"

    return s.request(
        method=method,
        url=dest,
        headers=headers,
        verify=verify_tls,
        data=content,
        stream=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Signs and sends a federation request to a matrix homeserver"
    )

    parser.add_argument(
        "-N",
        "--server-name",
        help="Name to give as the local homeserver. If unspecified, will be "
        "read from the config file.",
    )

    parser.add_argument(
        "-k",
        "--signing-key-path",
        help="Path to the file containing the private ed25519 key to sign the "
        "request with.",
    )

    parser.add_argument(
        "-c",
        "--config",
        default="homeserver.yaml",
        help="Path to server config file. Ignored if --server-name and "
        "--signing-key-path are both given.",
    )

    parser.add_argument(
        "-d",
        "--destination",
        default="matrix.org",
        help="name of the remote homeserver. We will do SRV lookups and "
        "connect appropriately.",
    )

    parser.add_argument(
        "-X",
        "--method",
        help="HTTP method to use for the request. Defaults to GET if --body is"
        "unspecified, POST if it is.",
    )

    parser.add_argument("--body", help="Data to send as the body of the HTTP request")

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )

    parser.add_argument(
        "path", help="request path, including the '/_matrix/federation/...' prefix."
    )

    args = parser.parse_args()

    args.signing_key = None
    if args.signing_key_path:
        with open(args.signing_key_path) as f:
            args.signing_key = f.readline()

    if not args.server_name or not args.signing_key:
        read_args_from_config(args)

    assert isinstance(args.signing_key, str)
    algorithm, version, key_base64 = args.signing_key.split()
    key = signedjson.key.decode_signing_key_base64(algorithm, version, key_base64)

    result = request(
        args.method,
        args.server_name,
        key,
        args.destination,
        args.path,
        content=args.body,
        verify_tls=not args.insecure,
    )

    sys.stderr.write("Status Code: %d\n" % (result.status_code,))

    for chunk in result.iter_content():
        # we write raw utf8 to stdout.
        sys.stdout.buffer.write(chunk)

    print("")


def read_args_from_config(args: argparse.Namespace) -> None:
    with open(args.config) as fh:
        config = yaml.safe_load(fh)

        if not args.server_name:
            args.server_name = config["server_name"]

        if not args.signing_key:
            if "signing_key" in config:
                args.signing_key = config["signing_key"]
            else:
                with open(config["signing_key_path"]) as f:
                    args.signing_key = f.readline()


class MatrixConnectionAdapter(HTTPAdapter):
    def send(
        self,
        request: PreparedRequest,
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        # overrides the send() method in the base class.

        # We need to look for .well-known redirects before passing the request up to
        # HTTPAdapter.send().
        assert isinstance(request.url, str)
        parsed = urlparse.urlsplit(request.url)
        server_name = parsed.netloc
        well_known = self._get_well_known(parsed.netloc)

        if well_known:
            server_name = well_known

        # replace the scheme in the uri with https, so that cert verification is done
        # also replace the hostname if we got a .well-known result
        request.url = urlparse.urlunsplit(
            ("https", server_name, parsed.path, parsed.query, parsed.fragment)
        )

        # at this point we also add the host header (otherwise urllib will add one
        # based on the `host` from the connection returned by `get_connection`,
        # which will be wrong if there is an SRV record).
        request.headers["Host"] = server_name

        return super().send(request, *args, **kwargs)

    def get_connection(
        self, url: str, proxies: Optional[Dict[str, str]] = None
    ) -> HTTPConnectionPool:
        # overrides the get_connection() method in the base class
        parsed = urlparse.urlsplit(url)
        (host, port, ssl_server_name) = self._lookup(parsed.netloc)
        print(
            f"Connecting to {host}:{port} with SNI {ssl_server_name}", file=sys.stderr
        )
        return self.poolmanager.connection_from_host(
            host,
            port=port,
            scheme="https",
            pool_kwargs={"server_hostname": ssl_server_name},
        )

    @staticmethod
    def _lookup(server_name: str) -> Tuple[str, int, str]:
        """
        Do an SRV lookup on a server name and return the host:port to connect to
        Given the server_name (after any .well-known lookup), return the host, port and
        the ssl server name
        """
        if server_name[-1] == "]":
            # ipv6 literal (with no port)
            return server_name, 8448, server_name

        if ":" in server_name:
            # explicit port
            out = server_name.rsplit(":", 1)
            try:
                port = int(out[1])
            except ValueError:
                raise ValueError("Invalid host:port '%s'" % (server_name,))
            return out[0], port, out[0]

        # Look up SRV for Matrix 1.8 `matrix-fed` service first
        try:
            srv = srvlookup.lookup("matrix-fed", "tcp", server_name)[0]
            print(
                f"SRV lookup on _matrix-fed._tcp.{server_name} gave {srv}",
                file=sys.stderr,
            )
            return srv.host, srv.port, server_name
        except Exception:
            pass
        # Fall back to deprecated `matrix` service
        try:
            srv = srvlookup.lookup("matrix", "tcp", server_name)[0]
            print(
                f"SRV lookup on _matrix._tcp.{server_name} gave {srv}",
                file=sys.stderr,
            )
            return srv.host, srv.port, server_name
        except Exception:
            # Fall even further back to just port 8448
            return server_name, 8448, server_name

    @staticmethod
    def _get_well_known(server_name: str) -> Optional[str]:
        if ":" in server_name:
            # explicit port, or ipv6 literal. Either way, no .well-known
            return None

        # TODO: check for ipv4 literals

        uri = f"https://{server_name}/.well-known/matrix/server"
        print(f"fetching {uri}", file=sys.stderr)

        try:
            resp = requests.get(uri)
            if resp.status_code != 200:
                print("%s gave %i" % (uri, resp.status_code), file=sys.stderr)
                return None

            parsed_well_known = resp.json()
            if not isinstance(parsed_well_known, dict):
                raise Exception("not a dict")
            if "m.server" not in parsed_well_known:
                raise Exception("Missing key 'm.server'")
            new_name = parsed_well_known["m.server"]
            print("well-known lookup gave %s" % (new_name,), file=sys.stderr)
            return new_name

        except Exception as e:
            print("Invalid response from %s: %s" % (uri, e), file=sys.stderr)
        return None


if __name__ == "__main__":
    main()
