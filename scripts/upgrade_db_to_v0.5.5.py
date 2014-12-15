from synapse.storage._base import SQLBaseStore
from synapse.storage.signatures import SignatureStore
from synapse.storage.event_federation import EventFederationStore

from syutil.base64util import encode_base64, decode_base64

from synapse.events import FrozenEvent
from synapse.events.builder import EventBuilder
from synapse.events.utils import prune_event

from synapse.crypto.event_signing import check_event_content_hash

from syutil.crypto.jsonsign import verify_signed_json, SignatureVerifyException
from syutil.crypto.signing_key import (
    decode_verify_key_bytes, write_signing_keys
)

import dns.resolver
import hashlib
import json
import sqlite3
import sys
import urllib2


class Store(object):
    _get_event_signatures_txn = SignatureStore.__dict__["_get_event_signatures_txn"]
    _get_event_content_hashes_txn = SignatureStore.__dict__["_get_event_content_hashes_txn"]
    _get_event_reference_hashes_txn = SignatureStore.__dict__["_get_event_reference_hashes_txn"]
    _get_prev_event_hashes_txn = SignatureStore.__dict__["_get_prev_event_hashes_txn"]
    _get_prev_events_and_state = EventFederationStore.__dict__["_get_prev_events_and_state"]
    _get_auth_events = EventFederationStore.__dict__["_get_auth_events"]
    cursor_to_dict = SQLBaseStore.__dict__["cursor_to_dict"]
    _simple_select_onecol_txn = SQLBaseStore.__dict__["_simple_select_onecol_txn"]
    _simple_select_list_txn = SQLBaseStore.__dict__["_simple_select_list_txn"]

    def _generate_event_json(self, txn, rows):
        sql = "SELECT * FROM events WHERE event_id = ? ORDER BY rowid asc"

        events = []
        for row in rows:
            d = dict(row)

            d.pop("stream_ordering", None)
            d.pop("topological_ordering", None)
            d.pop("processed", None)

            if "origin_server_ts" not in d:
                d["origin_server_ts"] = d.pop("ts", 0)
            else:
                d.pop("ts", 0)

            d.pop("prev_state", None)
            d.update(json.loads(d.pop("unrecognized_keys")))

            d["sender"] = d.pop("user_id")

            d["content"] = json.loads(d["content"])

            if "age_ts" not in d:
                # For compatibility
                d["age_ts"] = d.get("origin_server_ts", 0)

            d.setdefault("unsigned", {})["age_ts"] = d.pop("age_ts")

            d.pop("outlier", None)

            # d.pop("membership", None)

            d.pop("state_hash", None)

            d.pop("replaces_state", None)

            events.append(EventBuilder(d))

        for i, ev in enumerate(events):
            signatures = self._get_event_signatures_txn(
                txn, ev.event_id,
            )

            ev.signatures = {
                n: {
                    k: encode_base64(v) for k, v in s.items()
                }
                for n, s in signatures.items()
            }

            hashes = self._get_event_content_hashes_txn(
                txn, ev.event_id,
            )

            ev.hashes = {
                k: encode_base64(v) for k, v in hashes.items()
            }

            prevs = self._get_prev_events_and_state(txn, ev.event_id)

            ev.prev_events = [
                (e_id, h)
                for e_id, h, is_state in prevs
                if is_state == 0
            ]

            # ev.auth_events = self._get_auth_events(txn, ev.event_id)

            hashes = dict(ev.auth_events)

            for e_id, hash in ev.prev_events:
                if e_id in hashes and not hash:
                    hash.update(hashes[e_id])
            #
            # if hasattr(ev, "state_key"):
            #     ev.prev_state = [
            #         (e_id, h)
            #         for e_id, h, is_state in prevs
            #         if is_state == 1
            #     ]

        return [e.build() for e in events]


store = Store()


def get_key(server_name):
    print "Getting keys for: %s" % (server_name,)
    targets = []
    if ":" in server_name:
        target, port = server_name.split(":")
        targets.append((target, int(port)))
        return
    try:
        answers = dns.resolver.query("_matrix._tcp." + server_name, "SRV")
        for srv in answers:
            targets.append((srv.target, srv.port))
    except dns.resolver.NXDOMAIN:
        targets.append((server_name, 8448))
    except:
        print "Failed to lookup keys for %s" % (server_name,)
        return {}

    for target, port in targets:
        url = "https://%s:%i/_matrix/key/v1" % (target, port)
        try:
            keys = json.load(urllib2.urlopen(url, timeout=2))
            verify_keys = {}
            for key_id, key_base64 in keys["verify_keys"].items():
                verify_key = decode_verify_key_bytes(key_id, decode_base64(key_base64))
                verify_signed_json(keys, server_name, verify_key)
                verify_keys[key_id] = verify_key
            print "Got keys for: %s" % (server_name,)
            return verify_keys
        except urllib2.URLError:
            pass

    print "Failed to get keys for %s" % (server_name,)
    return {}


def get_events(cursor):
    # cursor.execute(
    #     "SELECT * FROM events WHERE event_id = ? ORDER BY rowid DESC",
    #     ("$14182049031533SMfTT:matrix.org",)
    # )

    # cursor.execute(
    #     "SELECT * FROM events ORDER BY rowid DESC LIMIT 10000"
    # )

    cursor.execute(
        "SELECT * FROM events ORDER BY rowid DESC"
    )

    rows = store.cursor_to_dict(cursor)

    events = store._generate_event_json(cursor, rows)

    print "Got events from DB."

    algorithms = {
        "sha256": hashlib.sha256,
    }

    server_keys = {}

    for event in events:
        for alg_name in event.hashes:
            if check_event_content_hash(event, algorithms[alg_name]):
                # print "PASS content hash %s" % (alg_name,)
                pass
            else:
                pass
                print "FAIL content hash %s %s" % (alg_name, event.event_id, )
                # print "%s %d" % (event.event_id, event.origin_server_ts)
                # print json.dumps(event.get_pdu_json(), indent=4, sort_keys=True)

        for host, sigs in event.signatures.items():
            pruned = prune_event(event)

            for key_id in sigs:
                if host not in server_keys:
                    server_keys[host] = get_key(host)
                if key_id in server_keys[host]:
                    try:
                        verify_signed_json(
                            pruned.get_pdu_json(),
                            host,
                            server_keys[host][key_id]
                        )
                    except SignatureVerifyException as e:
                        # print e
                        print "FAIL signature check %s %s" % (key_id, event.event_id)
                        # print json.dumps(pruned.get_pdu_json(), indent=4, sort_keys=True)

def main():
    conn = sqlite3.connect(sys.argv[1])
    cursor = conn.cursor()
    get_events(cursor)
    conn.commit()


if __name__ == "__main__":
    main()