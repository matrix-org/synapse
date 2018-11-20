#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2018 cuongnv

import requests
import uuid 
import urllib
import sqlite3
import time
import json

#Follow instruction
#1. List rooms
#2. Find admin of rooms
#3. Get access token of admin's room
#4. List old messages of that room
#5. Call redacted API clean message
#6. Clean up database

db_name = "homeserver.db"
host = "https://kent.im:8448/" #change to your host
ignore_rooms = ["!IlSUqXlIWoWWtqEpkU:kent.im", "!ozlDYAZeKTRPAVjXIU:kent.im"] #for testing
# ignore_rooms = []
is_mode_white_list = True
timeout = 2*60 #120s , for quick testing, change time as you need

def remove_message(roomId, eventId, access_token):
    payload = {"reason": "Timeout!"}
    roomId = urllib.quote(roomId)
    eventId = urllib.quote(eventId)
    headers = {'Authorization': 'Bearer ' + access_token}
    r = requests.post(host + "_matrix/client/api/v1/rooms/"+roomId+"/redact/"+eventId , json=payload, headers=headers, verify=False)
    return r.text

#1,2,3. List rooms & find admin of rooms & get access token

print ("-----[Auto Remove Message]-----")
if is_mode_white_list:
    print ("Mode: WhileList Some predefined rooms will be remove messages after time: {0} seconds)".format(timeout))
else:
    print ("Mode: BlackList (All rooms will be remove messages after time: {0} seconds)".format(timeout))
print ("Host: {0}".format(host))
print ("List predefined Rooms is: {0}".format(ignore_rooms))

conn = sqlite3.connect(db_name)
c = conn.cursor()
sql = "SELECT room_id, token, user_id FROM rooms, access_tokens WHERE rooms.creator = access_tokens.user_id"
if is_mode_white_list:
    if len(ignore_rooms) == 0:
        print ("[+] You must define list rooms to remove messages")
        exit(1)

if ignore_rooms:
    tmp = ""
    for ig in ignore_rooms:
        tmp += '"' + ig + '",'
    tmp = tmp[:len(tmp)-1]
    if is_mode_white_list:
        sql += " AND room_id IN (%s)" % tmp
    else:
        sql += " AND room_id NOT IN (%s)" % tmp
print ("[+] List rooms sql: {0}".format(sql))
roomCursor = c.execute(sql)
rooms = []
for row in roomCursor:
    print ("[+] Room: {0}".format(row[0]))
    rooms.append((row[0],row[1], row[2]))

#4. List old messages of that room
messages = []
for room in rooms:
    print ("[+] Room: {0} , Creator: {1}".format(room[0],room[2]))
    sql = "SELECT room_id, event_id, origin_server_ts, type FROM events WHERE room_id='%s' and (event_id not IN (select redacts from redactions)) and (type='m.room.encrypted' or type='m.room.message')" % room[0]
    print ("[+] SQL Command: {0}".format(sql))
    events = c.execute(sql)
    for row2 in events:
        diff = time.time() - int(row2[2])/1000
        print ("[+] Id: {0} Diff: {1}".format(row2[1], diff))
        if diff > timeout:
            messages.append((row2[0], row2[1], room[1])) #room_id, event_id, access_token

conn.commit()
conn.close()

print (messages)

#5. Call redacted API clean message
#remove message 
for message in messages:
    remove_message(message[0], message[1], message[2])
    time.sleep(3)

#6. Clean up database (remove all event)
if messages:    
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    removed_messages = []
    for row in c.execute("select redacts from redactions"):
        removed_messages.append(row[0])
    print ("[+] Remove messages {0}".format(removed_messages))

    tables = ["events", "rejections",  "event_json", "state_events", "current_state_events",
     "room_memberships", "feedback", "topics", "room_names", "state_groups", "event_to_state_groups",
     "event_forward_extremities", "event_backward_extremities", "event_edges", "event_destinations",
     "state_forward_extremities","event_edge_hashes","event_signatures","event_backward_extremities",
     "event_edges","event_destinations","state_forward_extremities", "event_reference_hashes","event_content_hashes",
     "redactions", "guest_access", "history_visibility", "event_push_actions","ex_outlier_stream", "event_reports",
     "stream_ordering_to_exterm", "event_auth","current_state_delta_stream", "event_push_actions_staging"]
    for msg in removed_messages:
        for tbl in tables:
            sql = 'DELETE FROM '+tbl+' WHERE event_id="%s"' % msg
            print (sql)
            c.execute(sql)

    conn.commit()
    conn.close()


