from __future__ import print_function

import argparse
import itertools
import json
import sys

from mock import Mock

from synapse.api.auth import Auth
from synapse.events import FrozenEvent


def check_auth(auth, auth_chain, events):
    auth_chain.sort(key=lambda e: e.depth)

    auth_map = {e.event_id: e for e in auth_chain}

    create_events = {}
    for e in auth_chain:
        if e.type == "m.room.create":
            create_events[e.room_id] = e

    for e in itertools.chain(auth_chain, events):
        auth_events_list = [auth_map[i] for i, _ in e.auth_events]

        auth_events = {(e.type, e.state_key): e for e in auth_events_list}

        auth_events[("m.room.create", "")] = create_events[e.room_id]

        try:
            auth.check(e, auth_events=auth_events)
        except Exception as ex:
            print("Failed:", e.event_id, e.type, e.state_key)
            print("Auth_events:", auth_events)
            print(ex)
            print(json.dumps(e.get_dict(), sort_keys=True, indent=4))
            # raise
        print("Success:", e.event_id, e.type, e.state_key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'json', nargs='?', type=argparse.FileType('r'), default=sys.stdin
    )

    args = parser.parse_args()

    js = json.load(args.json)

    auth = Auth(Mock())
    check_auth(
        auth,
        [FrozenEvent(d) for d in js["auth_chain"]],
        [FrozenEvent(d) for d in js.get("pdus", [])],
    )
