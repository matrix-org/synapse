import argparse
import hashlib
import json
import logging
import sys

from unpaddedbase64 import encode_base64

from synapse.crypto.event_signing import (
    check_event_content_hash,
    compute_event_reference_hash,
)


class dictobj(dict):
    def __init__(self, *args, **kargs):
        dict.__init__(self, *args, **kargs)
        self.__dict__ = self

    def get_dict(self):
        return dict(self)

    def get_full_dict(self):
        return dict(self)

    def get_pdu_json(self):
        return dict(self)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input_json", nargs="?", type=argparse.FileType('r'), default=sys.stdin
    )
    args = parser.parse_args()
    logging.basicConfig()

    event_json = dictobj(json.load(args.input_json))

    algorithms = {"sha256": hashlib.sha256}

    for alg_name in event_json.hashes:
        if check_event_content_hash(event_json, algorithms[alg_name]):
            print("PASS content hash %s" % (alg_name,))
        else:
            print("FAIL content hash %s" % (alg_name,))

    for algorithm in algorithms.values():
        name, h_bytes = compute_event_reference_hash(event_json, algorithm)
        print("Reference hash %s: %s" % (name, encode_base64(h_bytes)))


if __name__ == "__main__":
    main()
