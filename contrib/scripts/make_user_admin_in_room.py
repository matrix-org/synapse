#!/usr/bin/env python

import json
import sys
import urllib
from argparse import ArgumentParser

import requests


def _mkurl(template, kws):
    for key in kws:
        template = template.replace(key, kws[key])
    return template


def main(hs, room_id, access_token, user_id):
    headers = {"Authorization": "***" % (access_token)}
    room_state_url = _mkurl(
        "$HS/_matrix/client/api/v1/rooms/$ROOM/state?access_token=$TOKEN",
        {"$HS": hs, "$ROOM": room_id, "$TOKEN": access_token},
    )
    print("Getting room state => %s\n" % room_state_url)
    res = requests.get(room_state_url)
    print("HTTP %s\n" % res.status_code)
    state_events = res.json()
    if "error" in state_events:
        print("FATAL")
        print(state_events)
        return

    print("The following user IDs will be made an admin in %s" % room_id)
    print(user_id)
    doit = input("\nContinue? [Y]es")
    if len(doit) > 0 and doit.lower() == "y":
        admin_url = "%s/_synapse/admin/v1/rooms/%s/make_room_admin" % (hs, room_id)
        admin_body = {"user_id": user_id}
        print("Making request...")
        res = requests.post(admin_url, data=json.dumps(admin_body), headers=headers)
        if res.status_code != 200:
            print("ERROR: HTTP %s" % res.status_code)
        if res.json().get("error"):
            print("ERROR: JSON %s" % res.json())


if __name__ == "__main__":
    parser = ArgumentParser("Make target user an admin of the given room")
    parser.add_argument("-u", "--user-id", help="The user ID to make an admin")
    parser.add_argument("-t", "--token", help="Your access_token")
    parser.add_argument("-r", "--room", help="The room ID to target")
    parser.add_argument(
        "-s", "--homeserver", help="The base HS url e.g. http://matrix.org"
    )
    args = parser.parse_args()
    if not args.room or not args.token or not args.user_id or not args.homeserver:
        parser.print_help()
        sys.exit(1)
    else:
        main(args.homeserver, args.room, args.token, args.user_id)
