
from synapse.storage import SCHEMA_VERSION, read_schema
from synapse.storage._base import SQLBaseStore
from synapse.storage.signatures import SignatureStore
from synapse.storage.event_federation import EventFederationStore

from syutil.base64util import encode_base64, decode_base64

from synapse.crypto.event_signing import compute_event_signature

from synapse.events.builder import EventBuilder
from synapse.events.utils import prune_event

from synapse.crypto.event_signing import check_event_content_hash

from syutil.crypto.jsonsign import (
    verify_signed_json, SignatureVerifyException,
)
from syutil.crypto.signing_key import decode_verify_key_bytes

from syutil.jsonutil import encode_canonical_json

import argparse
# import dns.resolver
import hashlib
import httplib
import json
import sqlite3
import syutil
import urllib2


delta_sql = """
CREATE TABLE IF NOT EXISTS event_json(
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    internal_metadata NOT NULL,
    json BLOB NOT NULL,
    CONSTRAINT ev_j_uniq UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS event_json_id ON event_json(event_id);
CREATE INDEX IF NOT EXISTS event_json_room_id ON event_json(room_id);

PRAGMA user_version = 10;
"""


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
    _simple_insert_txn = SQLBaseStore.__dict__["_simple_insert_txn"]

    def _generate_event_json(self, txn, rows):
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

            outlier = d.pop("outlier", False)

            # d.pop("membership", None)

            d.pop("state_hash", None)

            d.pop("replaces_state", None)

            b = EventBuilder(d)
            b.internal_metadata.outlier = outlier

            events.append(b)

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


# def get_key(server_name):
#     print "Getting keys for: %s" % (server_name,)
#     targets = []
#     if ":" in server_name:
#         target, port = server_name.split(":")
#         targets.append((target, int(port)))
#     try:
#         answers = dns.resolver.query("_matrix._tcp." + server_name, "SRV")
#         for srv in answers:
#             targets.append((srv.target, srv.port))
#     except dns.resolver.NXDOMAIN:
#         targets.append((server_name, 8448))
#     except:
#         print "Failed to lookup keys for %s" % (server_name,)
#         return {}
#
#     for target, port in targets:
#         url = "https://%s:%i/_matrix/key/v1" % (target, port)
#         try:
#             keys = json.load(urllib2.urlopen(url, timeout=2))
#             verify_keys = {}
#             for key_id, key_base64 in keys["verify_keys"].items():
#                 verify_key = decode_verify_key_bytes(
#                     key_id, decode_base64(key_base64)
#                 )
#                 verify_signed_json(keys, server_name, verify_key)
#                 verify_keys[key_id] = verify_key
#             print "Got keys for: %s" % (server_name,)
#             return verify_keys
#         except urllib2.URLError:
#             pass
#         except urllib2.HTTPError:
#             pass
#         except httplib.HTTPException:
#             pass
#
#     print "Failed to get keys for %s" % (server_name,)
#     return {}


def reinsert_events(cursor, server_name, signing_key):
    print "Running delta: v10"

    cursor.executescript(delta_sql)

    cursor.execute(
        "SELECT * FROM events ORDER BY rowid ASC"
    )

    print "Getting events..."

    rows = store.cursor_to_dict(cursor)

    events = store._generate_event_json(cursor, rows)

    print "Got events from DB."

    algorithms = {
        "sha256": hashlib.sha256,
    }

    key_id = "%s:%s" % (signing_key.alg, signing_key.version)
    verify_key = signing_key.verify_key
    verify_key.alg = signing_key.alg
    verify_key.version = signing_key.version

    server_keys = {
        server_name: {
            key_id: verify_key
        }
    }

    i = 0
    N = len(events)

    for event in events:
        if i % 100 == 0:
            print "Processed: %d/%d events" % (i,N,)
        i += 1

        # for alg_name in event.hashes:
        #     if check_event_content_hash(event, algorithms[alg_name]):
        #         pass
        #     else:
        #         pass
        #         print "FAIL content hash %s %s" % (alg_name, event.event_id, )

        have_own_correctly_signed = False
        for host, sigs in event.signatures.items():
            pruned = prune_event(event)

            for key_id in sigs:
                if host not in server_keys:
                    server_keys[host] = {}  # get_key(host)
                if key_id in server_keys[host]:
                    try:
                        verify_signed_json(
                            pruned.get_pdu_json(),
                            host,
                            server_keys[host][key_id]
                        )

                        if host == server_name:
                            have_own_correctly_signed = True
                    except SignatureVerifyException:
                        print "FAIL signature check %s %s" % (
                            key_id, event.event_id
                        )

        # TODO: Re sign with our own server key
        if not have_own_correctly_signed:
            sigs = compute_event_signature(event, server_name, signing_key)
            event.signatures.update(sigs)

            pruned = prune_event(event)

            for key_id in event.signatures[server_name]:
                verify_signed_json(
                    pruned.get_pdu_json(),
                    server_name,
                    server_keys[server_name][key_id]
                )

        event_json = encode_canonical_json(
            event.get_dict()
        ).decode("UTF-8")

        metadata_json = encode_canonical_json(
            event.internal_metadata.get_dict()
        ).decode("UTF-8")

        store._simple_insert_txn(
            cursor,
            table="event_json",
            values={
                "event_id": event.event_id,
                "room_id": event.room_id,
                "internal_metadata": metadata_json,
                "json": event_json,
            },
            or_replace=True,
        )


def main(database, server_name, signing_key):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    # Do other deltas:
    cursor.execute("PRAGMA user_version")
    row = cursor.fetchone()

    if row and row[0]:
        user_version = row[0]
        # Run every version since after the current version.
        for v in range(user_version + 1, 10):
            print "Running delta: %d" % (v,)
            sql_script = read_schema("delta/v%d" % (v,))
            cursor.executescript(sql_script)

    reinsert_events(cursor, server_name, signing_key)

    conn.commit()

    print "Success!"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("database")
    parser.add_argument("server_name")
    parser.add_argument(
        "signing_key", type=argparse.FileType('r'),
    )
    args = parser.parse_args()

    signing_key = syutil.crypto.signing_key.read_signing_keys(
        args.signing_key
    )

    main(args.database, args.server_name, signing_key[0])
