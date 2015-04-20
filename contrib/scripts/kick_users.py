#!/usr/bin/env python
from argparse import ArgumentParser
import json
import requests
import sys
import urllib

def _mkurl(template, kws):
    for key in kws:
        template = template.replace(key, kws[key])
    return template

def main(hs, room_id, access_token, user_id_prefix, why):
    if not why:
        why = "Automated kick."
    print "Kicking members on %s in room %s matching %s" % (hs, room_id, user_id_prefix)
    room_state_url = _mkurl(
        "$HS/_matrix/client/api/v1/rooms/$ROOM/state?access_token=$TOKEN",
        {
            "$HS": hs,
            "$ROOM": room_id,
            "$TOKEN": access_token
        }
    )
    print "Getting room state => %s" % room_state_url
    res = requests.get(room_state_url)
    print "HTTP %s" % res.status_code
    state_events = res.json()
    if "error" in state_events:
        print "FATAL"
        print state_events
        return

    kick_list = []
    room_name = room_id
    for event in state_events:
        if not event["type"] == "m.room.member":
            if event["type"] == "m.room.name":
                room_name = event["content"].get("name")
            continue
        if not event["content"].get("membership") == "join":
            continue
        if event["state_key"].startswith(user_id_prefix):
            kick_list.append(event["state_key"])

    if len(kick_list) == 0:
        print "No user IDs match the prefix '%s'" % user_id_prefix
        return

    print "The following user IDs will be kicked from %s" % room_name
    for uid in kick_list:
        print uid
    doit = raw_input("Continue? [Y]es\n")
    if len(doit) > 0 and doit.lower() == 'y':
        print "Kicking members..."
        # encode them all
        kick_list = [urllib.quote(uid) for uid in kick_list]
        for uid in kick_list:
            kick_url = _mkurl(
                "$HS/_matrix/client/api/v1/rooms/$ROOM/state/m.room.member/$UID?access_token=$TOKEN",
                {
                    "$HS": hs,
                    "$UID": uid,
                    "$ROOM": room_id,
                    "$TOKEN": access_token
                }
            )
            kick_body = {
                "membership": "leave",
                "reason": why
            }
            print "Kicking %s" % uid
            res = requests.put(kick_url, data=json.dumps(kick_body))
            if res.status_code != 200:
                print "ERROR: HTTP %s" % res.status_code
            if res.json().get("error"):
                print "ERROR: JSON %s" % res.json()
            
    

if __name__ == "__main__":
    parser = ArgumentParser("Kick members in a room matching a certain user ID prefix.")
    parser.add_argument("-u","--user-id",help="The user ID prefix e.g. '@irc_'")
    parser.add_argument("-t","--token",help="Your access_token")
    parser.add_argument("-r","--room",help="The room ID to kick members in")
    parser.add_argument("-s","--homeserver",help="The base HS url e.g. http://matrix.org")
    parser.add_argument("-w","--why",help="Reason for the kick. Optional.")
    args = parser.parse_args()
    if not args.room or not args.token or not args.user_id or not args.homeserver:
        parser.print_help()
        sys.exit(1)
    else:
        main(args.homeserver, args.room, args.token, args.user_id, args.why)
