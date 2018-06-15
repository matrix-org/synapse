#!/usr/bin/env python2

from sys import argv
from os import system
import sqlite3
import psycopg2

if len(argv) < 3 or (argv[1] != "sqlite" and argv[1] != "postgresql") or (argv[1] == "postgresql" and len(argv) < 6):
    print "Usage:"
    print "    " + argv[0] + " sqlite <path_to_db_file>"
    print "or"
    print "    " + argv[0] + " postgresql <host> <dbname> <user> <password>"
    quit()

db = None
if argv[1] == "sqlite":
    db = sqlite3.connect(argv[2])
    cur = db.cursor()
elif argv[1] == "postgresql":
    db = psycopg2.connect('host=' + argv[2] + ' dbname=' + argv[3] + ' user=' + argv[4] + ' password=' + argv[5])
    cur = db.cursor()
else:
    print "This should be unreachable, report a bug."
    quit()

with db:
    cur.execute('SELECT group_id FROM groups;')
    groups = cur.fetchall()
    for group in groups:
        group_id = group[0]
        cur.execute('SELECT * FROM group_users WHERE group_id = \'' + group_id + '\';')
        users = cur.fetchall()
        if not users:
            print "Deleting " + group_id
            cur.execute('DELETE FROM group_users WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_invites WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_rooms WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_summary_rooms WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_summary_room_categories WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_room_categories WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_summary_users WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_summary_roles WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_roles WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_attestations_renewals WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM group_attestations_remote WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM local_group_membership WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM local_group_updates WHERE group_id = \'' + group_id + '\';')
            cur.execute('DELETE FROM groups WHERE group_id = \'' + group_id + '\';')
    db.commit()
