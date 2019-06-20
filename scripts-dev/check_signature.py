
import argparse
import json
import logging
import sys
import urllib2

import dns.resolver
from signedjson.key import decode_verify_key_bytes, write_signing_keys
from signedjson.sign import verify_signed_json
from unpaddedbase64 import decode_base64


def get_targets(server_name):
    if ":" in server_name:
        target, port = server_name.split(":")
        yield (target, int(port))
        return
    try:
        answers = dns.resolver.query("_matrix._tcp." + server_name, "SRV")
        for srv in answers:
            yield (srv.target, srv.port)
    except dns.resolver.NXDOMAIN:
        yield (server_name, 8448)


def get_server_keys(server_name, target, port):
    url = "https://%s:%i/_matrix/key/v1" % (target, port)
    keys = json.load(urllib2.urlopen(url))
    verify_keys = {}
    for key_id, key_base64 in keys["verify_keys"].items():
        verify_key = decode_verify_key_bytes(key_id, decode_base64(key_base64))
        verify_signed_json(keys, server_name, verify_key)
        verify_keys[key_id] = verify_key
    return verify_keys


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("signature_name")
    parser.add_argument(
        "input_json", nargs="?", type=argparse.FileType('r'), default=sys.stdin
    )

    args = parser.parse_args()
    logging.basicConfig()

    server_name = args.signature_name
    keys = {}
    for target, port in get_targets(server_name):
        try:
            keys = get_server_keys(server_name, target, port)
            print("Using keys from https://%s:%s/_matrix/key/v1" % (target, port))
            write_signing_keys(sys.stdout, keys.values())
            break
        except Exception:
            logging.exception("Error talking to %s:%s", target, port)

    json_to_check = json.load(args.input_json)
    print("Checking JSON:")
    for key_id in json_to_check["signatures"][args.signature_name]:
        try:
            key = keys[key_id]
            verify_signed_json(json_to_check, args.signature_name, key)
            print("PASS %s" % (key_id,))
        except Exception:
            logging.exception("Check for key %s failed" % (key_id,))
            print("FAIL %s" % (key_id,))


if __name__ == '__main__':
    main()
